/*-
 * Copyright (c) 2010 The FreeBSD Foundation
 * Copyright (c) 2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * Copyright (c) 2010 Mikolaj Golub <to.my.trociny@gmail.com>
 * All rights reserved.
 *
 * This software was developed by Mikolaj Golub. The source is derived
 * from HAST developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <paths.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <pjdlog.h>

#include "control.h"
#include "event.h"
#include "hooks.h"
#include "synch.h"

/* Report processes that are running for too long not often than this value. */
#define	REPORT_INTERVAL	30

/* Are we initialized? */
static bool hooks_initialized = false;

/*
 * Keep all processes we forked on a global queue, so we can report nicely
 * when they finish or report that they are running for a long time.
 */
#define	HOOKPROC_MAGIC_ALLOCATED	0x80090ca
#define	HOOKPROC_MAGIC_ONLIST		0x80090c0
struct hookproc {
	/* Magic. */
	int	hp_magic;
	/* PID of a forked child. */
	pid_t	hp_pid;
	/* When process were forked? */
	time_t	hp_birthtime;
	/* When we logged previous reported? */
	time_t	hp_lastreport;
	/* Path to executable and all the arguments we passed. */
	char	hp_comm[PATH_MAX];
	/* Info about hook caller. */
	struct hook_caller *hp_caller;
	TAILQ_ENTRY(hookproc) hp_next;
};
static TAILQ_HEAD(, hookproc) hookprocs;
static pthread_mutex_t hookprocs_lock;

static void hook_remove(struct hookproc *hp);
static void hook_free(struct hookproc *hp);

struct hook_caller *
hook_caller_alloc(struct hast_resource *res, int event)
{
	struct hook_caller *caller;
	
	caller = malloc(sizeof(*caller));
	if (caller == NULL) {
		return NULL;
	}
	
	caller->hc_magic = HOOKCALLER_MAGIC;
	caller->hc_res = res;
	caller->hc_event = event;	

	return caller;
}

void
hook_caller_free(struct hook_caller *caller)
{
	if (caller != NULL) {
		assert(caller->hc_magic == HOOKCALLER_MAGIC);
	
		caller->hc_magic = 0;
		free(caller);
	}
}

static void
descriptors(void)
{
	int fd;

	/*
	 * Close all (or almost all) descriptors.
	 */
	if (pjdlog_mode_get() == PJDLOG_MODE_STD) {
		closefrom(MAX(MAX(STDIN_FILENO, STDOUT_FILENO),
		    STDERR_FILENO) + 1);
		return;
	}

	closefrom(0);

	/*
	 * Redirect stdin, stdout and stderr to /dev/null.
	 */
	fd = open(_PATH_DEVNULL, O_RDONLY);
	if (fd < 0) {
		pjdlog_errno(LOG_WARNING, "Unable to open %s for reading",
		    _PATH_DEVNULL);
	} else if (fd != STDIN_FILENO) {
		if (dup2(fd, STDIN_FILENO) < 0) {
			pjdlog_errno(LOG_WARNING,
			    "Unable to duplicate descriptor for stdin");
		}
		close(fd);
	}
	fd = open(_PATH_DEVNULL, O_WRONLY);
	if (fd < 0) {
		pjdlog_errno(LOG_WARNING, "Unable to open %s for writing",
		    _PATH_DEVNULL);
	} else {
		if (fd != STDOUT_FILENO && dup2(fd, STDOUT_FILENO) < 0) {
			pjdlog_errno(LOG_WARNING,
			    "Unable to duplicate descriptor for stdout");
		}
		if (fd != STDERR_FILENO && dup2(fd, STDERR_FILENO) < 0) {
			pjdlog_errno(LOG_WARNING,
			    "Unable to duplicate descriptor for stderr");
		}
		if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
			close(fd);
	}
}

static struct hookproc *
hook_find(pid_t pid)
{
	struct hookproc *hp;

#ifdef HAVE_MTX_OWNED	
	assert(mtx_owned(&hookprocs_lock));
#endif

	TAILQ_FOREACH(hp, &hookprocs, hp_next) {
		assert(hp->hp_magic == HOOKPROC_MAGIC_ONLIST);
		assert(hp->hp_pid > 0);

		if (hp->hp_pid == pid)
			break;
	}

	return (hp);
}

static struct hookproc *
hook_findbycaller(struct hook_caller *caller)
{
	struct hookproc *hp;

#ifdef HAVE_MTX_OWNED
	assert(mtx_owned(&hookprocs_lock));
#endif
	
	if (caller == NULL)
		return NULL;

	TAILQ_FOREACH(hp, &hookprocs, hp_next) {
		assert(hp->hp_magic == HOOKPROC_MAGIC_ONLIST);
		assert(hp->hp_pid > 0);

		if (hp->hp_caller == NULL)
			continue;
		if (hp->hp_caller->hc_res == caller->hc_res &&
		    hp->hp_caller->hc_event == caller->hc_event)
			break;
	}

	return (hp);
}

/*
 * Invalidate callers with hc_res == res in all hooks. 
 */
void
hook_invalidate_callers(struct hast_resource *res)
{
	
	struct hookproc *hp;

	mtx_lock(&hookprocs_lock);
	
	TAILQ_FOREACH(hp, &hookprocs, hp_next) {
		assert(hp->hp_magic == HOOKPROC_MAGIC_ONLIST);
		assert(hp->hp_pid > 0);

		if (hp->hp_caller == NULL)
			continue;
		if (hp->hp_caller->hc_res == res) {
			hook_caller_free(hp->hp_caller);
			hp->hp_caller = NULL;
		}
	}

	mtx_unlock(&hookprocs_lock);
}

void
hook_init(void)
{

	assert(!hooks_initialized);

	mtx_init(&hookprocs_lock);
	TAILQ_INIT(&hookprocs);
	hooks_initialized = true;
}

void
hook_fini(void)
{
	struct hookproc *hp;

	assert(hooks_initialized);

	mtx_lock(&hookprocs_lock);
	while ((hp = TAILQ_FIRST(&hookprocs)) != NULL) {
		assert(hp->hp_magic == HOOKPROC_MAGIC_ONLIST);
		assert(hp->hp_pid > 0);

		hook_remove(hp);
		hook_free(hp);
	}
	mtx_unlock(&hookprocs_lock);

	mtx_destroy(&hookprocs_lock);
	TAILQ_INIT(&hookprocs);
	hooks_initialized = false;
}

static struct hookproc *
hook_alloc(const char *path, char **args, struct hook_caller *caller)
{
	struct hookproc *hp, *oldhp;
	unsigned int ii;

	hp = malloc(sizeof(*hp));
	if (hp == NULL) {
		pjdlog_error("Unable to allocate %zu bytes of memory for a hook.",
		    sizeof(*hp));
		if (caller != NULL)
			control_send_event_status(caller->hc_res,
						  caller->hc_event,
						  HAST_STATE_UNKNOWN);
		hook_caller_free(caller);
		return (NULL);
	}

	(void)strlcpy(hp->hp_comm, path, sizeof(hp->hp_comm));
	/* We start at 2nd argument as we don't want to have exec name twice. */
	for (ii = 1; args[ii] != NULL; ii++) {
		(void)strlcat(hp->hp_comm, " ", sizeof(hp->hp_comm));
		(void)strlcat(hp->hp_comm, args[ii], sizeof(hp->hp_comm));
	}
	if (strlen(hp->hp_comm) >= sizeof(hp->hp_comm) - 1) {
		pjdlog_error("Exec path too long, correct configuration file.");
		if (caller != NULL)
			control_send_event_status(caller->hc_res,
			    caller->hc_event,
			    HAST_STATE_UNKNOWN);
		hook_caller_free(caller);
		free(hp);
		return (NULL);
	}
	hp->hp_pid = 0;
	hp->hp_birthtime = hp->hp_lastreport = time(NULL);
	hp->hp_magic = HOOKPROC_MAGIC_ALLOCATED;
	hp->hp_caller = caller;
	return (hp);
}

static void
hook_add(struct hookproc *hp, pid_t pid)
{

	assert(hp->hp_magic == HOOKPROC_MAGIC_ALLOCATED);
	assert(hp->hp_pid == 0);

	hp->hp_pid = pid;
	mtx_lock(&hookprocs_lock);
	hp->hp_magic = HOOKPROC_MAGIC_ONLIST;
	TAILQ_INSERT_TAIL(&hookprocs, hp, hp_next);
	mtx_unlock(&hookprocs_lock);
}

static void
hook_remove(struct hookproc *hp)
{

	assert(hp->hp_magic == HOOKPROC_MAGIC_ONLIST);
	assert(hp->hp_pid > 0);
#ifdef HAVE_MTX_OWNED
	assert(mtx_owned(&hookprocs_lock));
#endif

	TAILQ_REMOVE(&hookprocs, hp, hp_next);
	hp->hp_magic = HOOKPROC_MAGIC_ALLOCATED;
}

static void
hook_free(struct hookproc *hp)
{

	assert(hp->hp_magic == HOOKPROC_MAGIC_ALLOCATED);
	assert(hp->hp_pid > 0);

	hp->hp_magic = 0;
	hook_caller_free(hp->hp_caller);
	free(hp);
}

static void
hook_inform_one(struct hookproc *hp, int status)
{
	if (WIFSIGNALED(status)) {
		pjdlog_debug(1, "Hook was killed (pid=%u, signal=%d, cmd=[%s]).",
		    hp->hp_pid, WTERMSIG(status), hp->hp_comm);
	} else {
		pjdlog_debug(1, "Hook exited (pid=%u, exitcode=%d, cmd=[%s]).",
		    hp->hp_pid, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
		    hp->hp_comm);
	}
	if (hp->hp_caller != NULL)
		control_send_event_status(hp->hp_caller->hc_res,
		    hp->hp_caller->hc_event,
		    WEXITSTATUS(status));	
}

void
hook_check_one(pid_t pid, int status)
{
	struct hookproc *hp;

	mtx_lock(&hookprocs_lock);
	hp = hook_find(pid);
	if (hp == NULL) {
		mtx_unlock(&hookprocs_lock);
		pjdlog_debug(1, "Unknown process pid=%u", pid);
		return;
	}
	hook_remove(hp);
	mtx_unlock(&hookprocs_lock);
	hook_inform_one(hp, status);
	hook_free(hp);
}

void
hook_check(void)
{
	struct hookproc *hp, *hp2;
	int status;
	time_t now;
	pid_t pid;

	assert(hooks_initialized);

	/*
	 * Report about processes that are running for a long time.
	 */
	now = time(NULL);
	mtx_lock(&hookprocs_lock);
	TAILQ_FOREACH_SAFE(hp, &hookprocs, hp_next, hp2) {
		assert(hp->hp_magic == HOOKPROC_MAGIC_ONLIST);
		assert(hp->hp_pid > 0);

		/*
		 * If process doesn't exists we somehow missed it.
		 * Not much can be done expect for logging this situation.
		 */
		if (kill(hp->hp_pid, 0) == -1 && errno == ESRCH) {			
			/*
			 * On FreeBSD if a child exited but wait() was
			 * not called, the above kill(pid, 0) would
			 * return success. On NetBSD it would fail, so
			 * here we check this.
			 */
			if(waitpid(hp->hp_pid, &status, WNOHANG) == hp->hp_pid)
				hook_inform_one(hp, status);
			else
				pjdlog_warning("Hook disappeared (pid=%u, cmd=[%s]).",
				    hp->hp_pid, hp->hp_comm);
			hook_remove(hp);
			hook_free(hp);				
			continue;
		}

		/*
		 * Skip proccesses younger than 1 minute.
		 */
		if (now - hp->hp_lastreport < REPORT_INTERVAL)
			continue;

		/*
		 * Hook is running for too long, report it.
		 */
		pjdlog_warning("Hook is running for %ju seconds (pid=%u, cmd=[%s]).",
		    (uintmax_t)(now - hp->hp_birthtime), hp->hp_pid,
		    hp->hp_comm);
		hp->hp_lastreport = now;
	}
	mtx_unlock(&hookprocs_lock);
}

void
hook_exec(struct hook_caller *caller, const char *path, ...)
{
	va_list ap;

	va_start(ap, path);
	hook_execv(caller, path, ap);
	va_end(ap);
}

void
hook_execv(struct hook_caller *caller, const char *path, va_list ap)
{
	struct hookproc *hp;
	char *args[64];
	unsigned int ii;
	pid_t pid;
	sigset_t mask;

	assert(hooks_initialized);

	if (path == NULL || path[0] == '\0')
		return;

	memset(args, 0, sizeof(args));
	args[0] = basename((char *)path);
	for (ii = 1; ii < sizeof(args) / sizeof(args[0]); ii++) {
		args[ii] = va_arg(ap, char *);
		if (args[ii] == NULL)
			break;
	}
	assert(ii < sizeof(args) / sizeof(args[0]));

	if (caller != NULL) {
		hook_check();
		mtx_lock(&hookprocs_lock);
		hp = hook_findbycaller(caller);
		if (hp != NULL) {
			pjdlog_error("Earlier started hook is still running (pid=%u, cmd=[%s]). Will not start new one.",
			    hp->hp_pid, hp->hp_comm);		
			mtx_unlock(&hookprocs_lock);
			control_send_event_status(caller->hc_res, caller->hc_event,
			    HAST_STATE_UNKNOWN);
			hook_caller_free(caller);
			return;
		}
		mtx_unlock(&hookprocs_lock);
	}
	hp = hook_alloc(path, args, caller);
	if (hp == NULL)
		return;

	pid = fork();
	switch (pid) {
	case -1:	/* Error. */
		pjdlog_errno(LOG_ERR, "Unable to fork to execute %s", path);
		hook_free(hp);		
		return;
	case 0:		/* Child. */
		descriptors();
		PJDLOG_VERIFY(sigemptyset(&mask) == 0);
		PJDLOG_VERIFY(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
		execv(path, args);
		pjdlog_errno(LOG_ERR, "Unable to execute %s", path);
		exit(EX_SOFTWARE);
	default:	/* Parent. */
		hook_add(hp, pid);
		break;
	}
}
