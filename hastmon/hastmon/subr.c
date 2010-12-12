/*-
 * Copyright (c) 2010 The FreeBSD Foundation
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
#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <pjdlog.h>

#include "hast.h"
#include "subr.h"

const char *
role2str(int role)
{

	switch (role) {																			
	case HAST_ROLE_INIT:																				
		return ("init");
	case HAST_ROLE_PRIMARY:																			
		return ("primary");
	case HAST_ROLE_SECONDARY:																			
		return ("secondary");
	case HAST_ROLE_WATCHDOG:																			
		return ("watchdog");
	}
	return ("unknown");
}

const char *
state2str(int state)
{

	switch (state) {																		
	case HAST_STATE_READYTORUN:																				
		return ("ready to run");
	case HAST_STATE_STARTING:																				
		return ("starting");
	case HAST_STATE_RUN:																				
		return ("run");
	case HAST_STATE_STOPPING:																				
		return ("stopping");
	case HAST_STATE_STOPPED:																				
		return ("stopped");
	case HAST_STATE_FAILED:																				
		return ("failed");
	}
	return ("unknown");
}

/*
 * Complaints.
 */

/*
 * Expire old complaints and return how many remains.
 */
static int
complaints_expire(struct hast_resource *res)
{
	struct hast_complaint *cmpl, *cmpl_temp;
	time_t now;
	int ii;

	assert(res != NULL);
	
	now = time(NULL);
	ii = 0;
	TAILQ_FOREACH_SAFE(cmpl, &res->hr_complaints, c_next, cmpl_temp) {
		if (now - cmpl->c_time > res->hr_complaint_interval) {
			TAILQ_REMOVE(&res->hr_complaints, cmpl, c_next);
			free(cmpl);
		} else
			ii++;
	}
	return ii;
}


/*
 * Register a complaint exparing old ones. Return emount of complains in
 * the list.
 */
static int
complaints_register(struct hast_resource *res, time_t cmpl_time)
{
	struct hast_complaint *cmpl;
	
	if (cmpl_time > 0) {
		cmpl = calloc(1, sizeof(*cmpl));
		if (cmpl == NULL)
			pjdlog_warning("Unable to allocate memory for complaint");
		else {
			cmpl->c_time = cmpl_time;
			TAILQ_INSERT_HEAD(&res->hr_complaints, cmpl, c_next);
		}
	}
	return complaints_expire(res);
}

int
complaints_add(struct hast_resource *res)
{
	return complaints_register(res, time(NULL));
}

int
complaints_cnt(struct hast_resource *res)
{

	assert(res != NULL);
	
	return complaints_register(res, -1);
}

/*
 * Remove all complaints
 */
void
complaints_clear(struct hast_resource *res)
{
	struct hast_complaint *cmpl;

	assert(res != NULL);
	
	while ((cmpl = TAILQ_FIRST(&res->hr_complaints)) != NULL) {
		TAILQ_REMOVE(&res->hr_complaints, cmpl, c_next);
		free(cmpl);
	}
}

static void
descriptors(long maxfd)
{
	int fd;

	/*
	 * Close all descriptors.
	 */	
	for (fd = 0; fd <= maxfd; fd++) {
		switch (fd) {
		case STDIN_FILENO:
		case STDOUT_FILENO:
		case STDERR_FILENO:
			if (pjdlog_mode_get() == PJDLOG_MODE_STD)
				break;
			/* FALLTHROUGH */
		default:
			close(fd);
			break;
		}
	}
	if (pjdlog_mode_get() == PJDLOG_MODE_STD)
		return;
	/*
	 * Redirect stdin, stdout and stderr to /dev/null.
	 */
	fd = open(_PATH_DEVNULL, O_RDONLY);
	if (fd >= 0 && fd != STDIN_FILENO) {
		dup2(fd, STDIN_FILENO);
		close(fd);
	}
	fd = open(_PATH_DEVNULL, O_WRONLY);
	if (fd >= 0 ) {
		if (fd != STDOUT_FILENO)
			dup2(fd, STDOUT_FILENO);
		if (fd != STDERR_FILENO)
			dup2(fd, STDERR_FILENO);
		if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
			close(fd);
	}
}

int
check_resource(struct hast_resource *res)
{
	int status;
	long maxfd;
	pid_t pid;
	char *args[3];

	assert(res->hr_exec != NULL && res->hr_exec[0] != '\0');

	args[0] = res->hr_exec;
	args[1] = "status";
	args[2] = NULL;

	/*
	 * Find descriptor table size to pass it to descriptors(). We
	 * can't do this in descriptors() because it is called after
	 * fork() in in a multithreaded process and should not call
	 * any not async-signal safe functions.
	 */
	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd < 0) {
		pjdlog_errno(LOG_WARNING, "sysconf(_SC_OPEN_MAX) failed");
		maxfd = 1024;
	}
	
	pid = fork();
	switch (pid) {
	case -1:	/* Error. */
		pjdlog_errno(LOG_ERR, "Unable to fork to execute %s", res->hr_exec);
		return (-1);
	case 0:		/* Child. */
		descriptors(maxfd);
		execv(res->hr_exec, args);
		exit(EX_SOFTWARE);
	default:	/* Parent. */
		if (waitpid(pid, &status, 0) != pid) {
			pjdlog_errno(LOG_ERR,
				     "Waiting for process (pid=%u) failed",
				     (unsigned int)pid);
			return (-1);
		} else {
			return (WEXITSTATUS(status));
		}
	}
}
