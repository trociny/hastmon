/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
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

#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <nv.h>
#include <pjdlog.h>

#include "control.h"
#include "event.h"
#include "hast.h"
#include "hast_proto.h"
#include "hastmon.h"
#include "hooks.h"
#include "proto.h"
#include "subr.h"
#include "synch.h"

static struct hast_resource *gres;
/*
 * The lock below allows to avoid races when exit is initiated by two
 * threads simultaneosly.
 */
static pthread_mutex_t exit_lock;

static void *respond_thread(void *arg);
static void *local_check_thread(void *arg);


static void
init_remote(struct hast_remote *remote, struct nv *nvin)
{
	struct hast_resource *res;
	uint64_t resuid;
	struct nv *nvout;

	res = remote->r_res;
	nvout = nv_alloc();
	resuid = nv_get_uint64(nvin, "resuid");
	if (res->hr_resuid == 0) {
		/*
		 * Provider is used for the first time. Initialize everything.
		 */
		res->hr_resuid = resuid;
	}
	nv_add_uint64(nvout, resuid, "resuid");
	if (hast_proto_send(res, remote->r_in, nvout, NULL, 0) < 0) {
		pjdlog_errno(LOG_WARNING, "Unable to send to %s",
		    remote->r_addr);
		nv_free(nvout);
		exit(EX_TEMPFAIL);
	}
	nv_free(nvout);
}

void
hastmon_secondary(struct hast_remote *remote, struct nv *nvin)
{
	struct hast_resource *res;
	sigset_t mask;
	pthread_t td;
	pid_t pid;
	int error;

	res = remote->r_res;

	/*
	 * Empty complaints list.
	 */
	complaints_clear(res);
					
	/*
	 * Create communication channel between parent and child.
	 */
	if (proto_client("socketpair://", &res->hr_ctrl) < 0) {
		KEEP_ERRNO((void)pidfile_remove(pfh));
		pjdlog_exit(EX_OSERR,
		    "Unable to create control sockets between parent and child");
	}
	/*
	 * Create communication channel between child and parent.
	 */
	if (proto_client("socketpair://", &res->hr_event) < 0) {
		KEEP_ERRNO((void)pidfile_remove(pfh));
		pjdlog_exit(EX_OSERR,
		    "Unable to create event sockets between child and parent");
	}

	pid = fork();
	if (pid < 0) {
		KEEP_ERRNO((void)pidfile_remove(pfh));
		pjdlog_exit(EX_OSERR, "Unable to fork");
	}

	if (pid > 0) {
		/* This is parent. */
		proto_close(remote->r_in);
		remote->r_in = NULL;
		proto_close(remote->r_out);
		remote->r_out = NULL;
		/* Declare that we are receiver. */
		proto_recv(res->hr_event, NULL, 0);
		res->hr_workerpid = pid;
		return;
	}

	gres = res;

	(void)pidfile_close(pfh);
	hook_fini();

#if defined(HAVE_FUNC1_SETPROCTITLE_UNISTD_H) || \
	defined(HAVE_FUNC1_SETPROCTITLE_STDLIB_H) || \
	defined(HAVE_FUNC1_SETPROCTITLE_SETPROCTITLE_H)
	setproctitle("%s (secondary)", res->hr_name);
#endif

	PJDLOG_VERIFY(sigemptyset(&mask) == 0);
	PJDLOG_VERIFY(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

	synch_mtx_init(&exit_lock);
	synch_mtx_init(&res->hr_lock);

	/* Declare that we are sender. */
	proto_send(res->hr_event, NULL, 0);

	/* Error in setting timeout is not critical, but why should it fail? */
	if (proto_timeout(remote->r_in, 0) < 0)
		pjdlog_errno(LOG_WARNING, "Unable to set connection timeout");
	if (proto_timeout(remote->r_out, res->hr_timeout) < 0)
		pjdlog_errno(LOG_WARNING, "Unable to set connection timeout");

	/*
	 * Create the control thread before sending any event to the parent,
	 * as we can deadlock when parent sends control request to worker,
	 * but worker has no control thread started yet, so parent waits.
	 * In the meantime worker sends an event to the parent, but parent
	 * is unable to handle the event, because it waits for control
	 * request response.
	 */
	error = pthread_create(&td, NULL, ctrl_thread, res);
	assert(error == 0);
	init_remote(remote, nvin);
	error = pthread_create(&td, NULL, respond_thread, remote);
	assert(error == 0);
	event_send(res, EVENT_CONNECT);	
	(void)local_check_thread(res);
}

static void
reqlog(int loglevel, int debuglevel, int error, uint8_t cmd, const char *fmt, ...)
{
	char msg[1024];
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if ((size_t)len < sizeof(msg)) {
		switch (cmd) {
		case HIO_STATE:
			(void)snprintf(msg + len, sizeof(msg) - len,
			    "STATE(%u).", (unsigned int)cmd);
			break;
		default:
			(void)snprintf(msg + len, sizeof(msg) - len,
			    "UNKNOWN(%u).", (unsigned int)cmd);
			break;
		}
	}
	pjdlog_common(loglevel, debuglevel, error, "%s", msg);
}

static __dead2 void
secondary_exit(int exitcode, const char *fmt, ...)
{
	va_list ap;

	assert(exitcode != EX_OK);
	synch_mtx_lock(&exit_lock);
	va_start(ap, fmt);
	pjdlogv_errno(LOG_ERR, fmt, ap);
	va_end(ap);
	event_send(gres, EVENT_DISCONNECT);
	exit(exitcode);
}

/*
 * Thread receives requests from the primary node and answer.
 */
static void *
respond_thread(void *arg)
{
	struct hast_remote *remote = arg;
	struct hast_resource *res;
	struct nv *nvin, *nvout;
	uint8_t	cmd;
	int	error;

	res = remote->r_res;

	for (;;) {
		nvout = NULL;
		error = 0;

		if (hast_proto_recv_hdr(remote->r_in, &nvin) < 0) {
			secondary_exit(EX_TEMPFAIL,
			    "Unable to receive request header");
		}
		
		nvout = nv_alloc();
		/* Copy sequence number. */
		nv_add_uint64(nvout, nv_get_uint64(nvin, "seq"), "seq");
		
		cmd = nv_get_uint8(nvin, "cmd");
		reqlog(LOG_DEBUG, 2, -1, cmd,
		       "respond: Got request header: ");
		switch (cmd) {
		case HIO_STATE:
			synch_mtx_lock(&res->hr_lock);
			remote->r_state = nv_get_uint8(nvin, "state");
			pjdlog_debug(2, "respond: Setting remote state to %s (%u).",
			    state2str(remote->r_state),
			    (unsigned int)remote->r_state);
			pjdlog_debug(2, "respond: Local state is %s (%u).",
			    state2str(res->hr_local_state),
			    (unsigned int)res->hr_local_state);
			nv_add_uint8(nvout, res->hr_local_state, "state");
			synch_mtx_unlock(&res->hr_lock);
			break;
		default:
			pjdlog_error("Header contains invalid 'cmd' (%hhu).",
			    (unsigned int)cmd);
			nv_add_int16(nvout, EINVAL, "error");
		}
		if (nv_error(nvout) != 0) {
			pjdlog_error("Unable to create answer.");
			goto nv_free;
		}
		if (hast_proto_send(res, remote->r_out, nvout, NULL, 0) < 0) {
			secondary_exit(EX_TEMPFAIL, "Unable to send reply.");
		}
	nv_free:
		nv_free(nvin);
		nv_free(nvout);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Thread checks the local status of the resource.
 */
static void *
local_check_thread(void *arg)
{
	struct hast_resource *res = arg;

	for (;;) {
		pjdlog_debug(2, "local_check: Sending status event to check local state.");
		event_send(res, EVENT_STATUS);
		pjdlog_debug(2, "local_check: Sleeping for %d sec.", res->hr_heartbeat_interval);
		sleep(res->hr_heartbeat_interval);
		synch_mtx_lock(&res->hr_lock);
		pjdlog_debug(2, "local_check: Local state is %s (%u).",
		    state2str(res->hr_local_state),
		    (unsigned int)res->hr_local_state);
		if (res->hr_local_state != HAST_STATE_STOPPED) {
			res->hr_local_state = HAST_STATE_STOPPING;
			synch_mtx_unlock(&res->hr_lock);
			pjdlog_debug(2, "local_check: Stopping resource.");
			event_send(res, EVENT_STOP);
			pjdlog_debug(2, "local_check: Sleeping for %d sec.", res->hr_heartbeat_interval);
			sleep(res->hr_heartbeat_interval);			
		} else
			synch_mtx_unlock(&res->hr_lock);
	}
	/* NOTREACHED */
	return (NULL);
}
