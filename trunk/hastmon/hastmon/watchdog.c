/*-
 * Copyright (c) 2009 The FreeBSD Foundation
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
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/time.h>
#include <sys/refcount.h>
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

#include "control.h"
#include "event.h"
#include "hast.h"
#include "hast_proto.h"
#include "hastmon.h"
#include "proto.h"
#include "pjdlog.h"
#include "subr.h"
#include "synch.h"

#define HIO_UNKNOWN	0
#define HIO_CHECK	1
#define HIO_COMPLAINT	2

struct remote_status {
	int	rs_role;
	int	rs_state;
	int	rs_error;
};

struct hio {
	/* Sequence number */
	uint64_t		hio_seq;
	/* Command */
	uint8_t			hio_cmd;
	/*
	 * Number of components we are still waiting for.
	 * Each component has to decrease this counter by one
	 * even on failure.
	 */
	unsigned int		 hio_countdown;
	/*
	 * Each component has a place to store remote node status and
	 * its own error. Once the request is handled by all
	 * components we can decide if the request overall is
	 * successful or not.
	 */
	struct remote_status	*hio_status;
	TAILQ_ENTRY(hio)	*hio_next;
};
#define	hio_free_next	hio_next[0]
#define	hio_done_next	hio_next[0]

/*
 * Free list holds unused structures. When free list is empty, we have to wait
 * until some in-progress requests are freed.
 */
static TAILQ_HEAD(, hio) hio_free_list;
static pthread_mutex_t hio_free_list_lock;
static pthread_cond_t hio_free_list_cond;
/*
 * There is one send list for every component. One requests is placed on all
 * send lists - each component gets the same request, but each component is
 * responsible for managing his own send list.
 */
static TAILQ_HEAD(, hio) *hio_send_list;
static pthread_mutex_t *hio_send_list_lock;
static pthread_cond_t *hio_send_list_cond;
/*
 * Request is placed on done list by the slowest component (the one that
 * decreased hio_countdown from 1 to 0).
 */
static TAILQ_HEAD(, hio) hio_done_list;
static pthread_mutex_t hio_done_list_lock;
static pthread_cond_t hio_done_list_cond;
/*
 * Guard lock.
 */
static pthread_mutex_t hio_guard_lock;
static pthread_cond_t hio_guard_cond;

/*
 * Maximum number of outstanding I/O requests.
 */
#define	HAST_HIO_MAX	256

#define	RETRY_SLEEP		10

#define	ISCONNECTED(res, no)	\
	(TAILQ_FIRST(&(res)->hr_remote)->r_in != NULL && TAILQ_FIRST(&(res)->hr_remote)->r_out != NULL)

#define	QUEUE_INSERT1(hio, name, ncomp)	do {				\
	bool _wakeup;							\
									\
	mtx_lock(&hio_##name##_list_lock[(ncomp)]);			\
	_wakeup = TAILQ_EMPTY(&hio_##name##_list[(ncomp)]);		\
	TAILQ_INSERT_TAIL(&hio_##name##_list[(ncomp)], (hio),		\
	    hio_next[(ncomp)]);						\
	mtx_unlock(&hio_##name##_list_lock[ncomp]);			\
	if (_wakeup)							\
		cv_signal(&hio_##name##_list_cond[(ncomp)]);		\
} while (0)
#define	QUEUE_INSERT2(hio, name)	do {				\
	bool _wakeup;							\
									\
	mtx_lock(&hio_##name##_list_lock);				\
	_wakeup = TAILQ_EMPTY(&hio_##name##_list);			\
	TAILQ_INSERT_TAIL(&hio_##name##_list, (hio), hio_##name##_next);\
	mtx_unlock(&hio_##name##_list_lock);				\
	if (_wakeup)							\
		cv_signal(&hio_##name##_list_cond);			\
} while (0)
#define	QUEUE_TAKE1(hio, name, ncomp)	do {				\
	mtx_lock(&hio_##name##_list_lock[(ncomp)]);			\
	while (((hio) = TAILQ_FIRST(&hio_##name##_list[(ncomp)])) == NULL) { \
		cv_wait(&hio_##name##_list_cond[(ncomp)],		\
		    &hio_##name##_list_lock[(ncomp)]);			\
	}								\
	TAILQ_REMOVE(&hio_##name##_list[(ncomp)], (hio),		\
	    hio_next[(ncomp)]);						\
	mtx_unlock(&hio_##name##_list_lock[(ncomp)]);			\
} while (0)
#define	QUEUE_TAKE2(hio, name)	do {					\
	mtx_lock(&hio_##name##_list_lock);				\
	while (((hio) = TAILQ_FIRST(&hio_##name##_list)) == NULL) {	\
		cv_wait(&hio_##name##_list_cond,			\
		    &hio_##name##_list_lock);				\
	}								\
	TAILQ_REMOVE(&hio_##name##_list, (hio), hio_##name##_next);	\
	mtx_unlock(&hio_##name##_list_lock);				\
} while (0)

static struct hast_resource *gres;

static void *heartbeat_start_thread(void *arg);
static void *remote_send_thread(void *arg);
static void *heartbeat_end_thread(void *arg);
static void *guard_thread(void *arg);

static void
cleanup(struct hast_resource *res)
{

}

static void
watchdog_exit(int exitcode, const char *fmt, ...)
{
	va_list ap;

	assert(exitcode != EX_OK);
	va_start(ap, fmt);
	pjdlogv_errno(LOG_ERR, fmt, ap);
	va_end(ap);
	cleanup(gres);
	exit(exitcode);
}

static void
watchdog_exitx(int exitcode, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	pjdlogv(exitcode == EX_OK ? LOG_INFO : LOG_ERR, fmt, ap);
	va_end(ap);
	cleanup(gres);
	exit(exitcode);
}

static void
init_environment(struct hast_resource *res)
{
	struct hast_remote *remote;
	struct hio *hio;
	unsigned int ii, ncomps;
	sigset_t mask;

	/*
	 * In the future it might be per-resource value.
	 */
	ncomps = res->hr_remote_cnt;

	/*
	 * Allocate memory needed by lists.
	 */
	hio_send_list = malloc(sizeof(hio_send_list[0]) * ncomps);
	if (hio_send_list == NULL) {
		watchdog_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for send lists.",
		    sizeof(hio_send_list[0]) * ncomps);
	}
	hio_send_list_lock = malloc(sizeof(hio_send_list_lock[0]) * ncomps);
	if (hio_send_list_lock == NULL) {
		watchdog_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for send list locks.",
		    sizeof(hio_send_list_lock[0]) * ncomps);
	}
	hio_send_list_cond = malloc(sizeof(hio_send_list_cond[0]) * ncomps);
	if (hio_send_list_cond == NULL) {
		watchdog_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for send list condition variables.",
		    sizeof(hio_send_list_cond[0]) * ncomps);
	}

	/*
	 * Initialize lists, their locks and theirs condition variables.
	 */
	TAILQ_INIT(&hio_free_list);
	mtx_init(&hio_free_list_lock);
	cv_init(&hio_free_list_cond);
	for (ii = 0; ii < ncomps; ii++) {
		TAILQ_INIT(&hio_send_list[ii]);
		mtx_init(&hio_send_list_lock[ii]);
		cv_init(&hio_send_list_cond[ii]);
	}
	TAILQ_INIT(&hio_done_list);
	mtx_init(&hio_done_list_lock);
	cv_init(&hio_done_list_cond);
	mtx_init(&hio_guard_lock);
	cv_init(&hio_guard_cond);

	/*
	 * Allocate requests pool and initialize requests.
	 */
	for (ii = 0; ii < HAST_HIO_MAX; ii++) {
		hio = malloc(sizeof(*hio));
		if (hio == NULL) {
			watchdog_exitx(EX_TEMPFAIL,
			    "Unable to allocate %zu bytes of memory for hio request.",
			    sizeof(*hio));
		}
		hio->hio_cmd = HIO_UNKNOWN;
		hio->hio_countdown = 0;
		hio->hio_status = malloc(sizeof(hio->hio_status[0]) * ncomps);
		if (hio->hio_status == NULL) {
			watchdog_exitx(EX_TEMPFAIL,
			    "Unable allocate %zu bytes of memory for hio statuses.",
			    sizeof(hio->hio_status[0]) * ncomps);
		}
		hio->hio_next = malloc(sizeof(hio->hio_next[0]) * ncomps);
		if (hio->hio_next == NULL) {
			watchdog_exitx(EX_TEMPFAIL,
			    "Unable allocate %zu bytes of memory for hio_next field.",
			    sizeof(hio->hio_next[0]) * ncomps);
		}
		TAILQ_INSERT_HEAD(&hio_free_list, hio, hio_free_next);
	}

	mtx_init(&res->hr_lock);	
	res->hr_local_state = HAST_STATE_UNKNOWN;
	TAILQ_FOREACH(remote, &res->hr_remote, r_next)
		remote->r_state = HAST_STATE_UNKNOWN;
	
	/*
	 * Turn on signals handling.
	 */
	PJDLOG_VERIFY(sigemptyset(&mask) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGHUP) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGINT) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGTERM) == 0);
	PJDLOG_VERIFY(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
}

void
hastmon_watchdog(struct hast_resource *res)
{
	pthread_t td;
	pid_t pid;
	int error;
	struct hast_remote *remote;

	gres = res;

	/*
	 * Create communication channel between parent and child.
	 */
	if (proto_client("socketpair://", &res->hr_ctrl) < 0) {
		KEEP_ERRNO((void)pidfile_remove(pfh));
		watchdog_exit(EX_OSERR,
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
		watchdog_exit(EX_TEMPFAIL, "Unable to fork");
	}

	if (pid > 0) {
		/* This is parent. */
		/* Declare that we are receiver. */
		proto_recv(res->hr_event, NULL, 0);
		pjdlog_debug(1, "hastmon_watchdog: setting res->hr_workerpid = pid");
		res->hr_workerpid = pid;
		return;
	}
	(void)pidfile_close(pfh);

	setproctitle("%s (watchdog)", res->hr_name);

	signal(SIGHUP, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);

	/* Declare that we are sender. */
	proto_send(res->hr_event, NULL, 0);
	
	init_environment(res);
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
	error = pthread_create(&td, NULL, heartbeat_start_thread, res);
	assert(error == 0);
	TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
		error = pthread_create(&td, NULL, remote_send_thread, remote);
		assert(error == 0);
	}
	error = pthread_create(&td, NULL, heartbeat_end_thread, res);
	assert(error == 0);
	(void)guard_thread(res);
}

/*
 * Threads initiate monitoring operations.
 */
static void *
heartbeat_start_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hast_remote *remote;
	struct hio *hio;
	unsigned int ii, ncomp, ncomps, countdown;
	int error, complain;

	ncomps = res->hr_remote_cnt;

	for (;;) {
		pjdlog_debug(2, "heartbeat_start: Taking free request.");
		QUEUE_TAKE2(hio, free);
		pjdlog_debug(2, "heartbeat_start: (%p) Got free request.", hio);
		complain = 1;
		countdown = 0;
		mtx_lock(&res->hr_lock);
		/* Check if primary is OK and send a complain to secondary if it is not */
		TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
			if (remote->r_role == HAST_ROLE_PRIMARY &&
			    remote->r_state == HAST_STATE_RUN)
				complain = 0;
			if (remote->r_role == HAST_ROLE_SECONDARY)
				countdown++;
		}
		if (complain && countdown > 0) {
			pjdlog_debug(2, "heartbeat_start: (%p) Moving complain request to the send queues.", hio);
			hio->hio_cmd = HIO_COMPLAINT;
			refcount_init(&hio->hio_countdown, countdown);
			pjdlog_debug(2, "heartbeat_start: (%p) Countdown is %d.", hio, hio->hio_countdown);		
			TAILQ_FOREACH(remote, &res->hr_remote, r_next)
				if (remote->r_role == HAST_ROLE_SECONDARY)
					QUEUE_INSERT1(hio, send, remote->r_ncomp);
			mtx_unlock(&res->hr_lock);
			/* Register the complaint */
			event_send(res, EVENT_COMPLAINT);
			/* Take free request for check */
			pjdlog_debug(2, "heartbeat_start: Taking free request.");
			QUEUE_TAKE2(hio, free);
			pjdlog_debug(2, "heartbeat_start: (%p) Got free request.", hio);
		} else
			mtx_unlock(&res->hr_lock);

		hio->hio_cmd = HIO_CHECK;
		for (ii = 0; ii < ncomps; ii++)
			hio->hio_status[ii].rs_error = 0;
		pjdlog_debug(2, "heartbeat_start: (%p) Moving check request to the send queues.", hio);
		refcount_init(&hio->hio_countdown, ncomps);
		pjdlog_debug(2, "heartbeat_start: (%p) Countdown is %d.", hio, hio->hio_countdown);		
		for (ii = 0; ii < ncomps; ii++)
			QUEUE_INSERT1(hio, send, ii);
		sleep(res->hr_heartbeat_interval);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Thread sends request to remote node.
 */
static void *
remote_send_thread(void *arg)
{
	struct hast_remote *remote = arg;
	struct hast_resource *res;
	struct proto_conn *conn;
	struct hio *hio;
	struct nv *nv;
	unsigned int ncomp, error;
	const char *str;
	uint64_t seq;

	res = remote->r_res;
	ncomp = remote->r_ncomp;
	
	for (seq = 1; ; seq++) {
		pjdlog_debug(2, "remote_send[%u]: Taking request.", ncomp);
		QUEUE_TAKE1(hio, send, ncomp);
		pjdlog_debug(2, "remote_send[%u]: (%p) Got request.", ncomp, hio);
		hio->hio_seq = seq;		
		nv = NULL;

		/* Setup connection... */
		if (proto_client(remote->r_addr, &conn) < 0) {
			pjdlog_debug(2,
			    "remote_send[%u]: (%p) Unable to setup connection to %s.",
			    ncomp, hio, remote->r_addr);
			hio->hio_status[ncomp].rs_error = errno;
			goto close;
		}
		/* ...and connect to hastmon. */
		if (proto_connect(conn) < 0) {
			pjdlog_debug(2,
			    "remote_send[%u]: (%p) Unable to connect to hastmon via %s.",
			    ncomp, hio, remote->r_addr);
			hio->hio_status[ncomp].rs_error = errno;
			goto close;
		}
		/* Send the command to the server... */
		nv = nv_alloc();
		if (hio->hio_cmd == HIO_COMPLAINT) {
			nv_add_string(nv, res->hr_name, "resource");
			nv_add_uint8(nv, HASTREQ_TYPE_COMPLAINT, "type");
			if (hast_proto_send(NULL, conn, nv, NULL, 0) < 0) {
				pjdlog_debug(2,
				    "remote_send[%u]: (%p) Unable to send a complain to hastmon via %s.",
				    ncomp, hio, remote->r_addr);
				hio->hio_status[ncomp].rs_error = errno;
			}
			goto close;
		}
		/* HIO_CHECK */
		nv_add_uint8(nv, HASTREQ_TYPE_CONTROL, "type");
		nv_add_uint8(nv, HASTCTL_CMD_STATUS, "cmd");
		nv_add_string(nv, res->hr_name, "resource%u", 0);
		if (hast_proto_send(NULL, conn, nv, NULL, 0) < 0) {
			pjdlog_debug(2,
			    "remote_send[%u]: (%p) Unable to send command to hastmon via %s.",
			    ncomp, hio, remote->r_addr);
			hio->hio_status[ncomp].rs_error = errno;
			goto close;
		}
		nv_free(nv);
		nv = NULL;
		/* ...and receive reply. */
		if (hast_proto_recv(NULL, conn, &nv, NULL, 0) < 0) {
			pjdlog_debug(2,
			    "remote_send[%u]: (%p) Cannot receive reply from hastmon via %s.",
			    ncomp, hio, remote->r_addr);
			hio->hio_status[ncomp].rs_error = errno;
			goto close;
		}

		error = nv_get_int16(nv, "error");
		if (error != 0) {
			pjdlog_debug(2,
			    "remote_send[%u]: (%p) Error %d received from hastmon.",
			    ncomp, hio, error);
			hio->hio_status[ncomp].rs_error = errno;
			goto close;
		}
		nv_set_error(nv, 0);

		str = nv_get_string(nv, "resource%u", 0);
		pjdlog_debug(2, "remote_send[%u]: (%p) %s:", ncomp, hio, str);
		hio->hio_status[ncomp].rs_role = nv_get_uint8(nv, "role%u", 0);
		pjdlog_debug(2, "remote_send[%u]: (%p)   role: %s", ncomp, hio,
		    role2str(hio->hio_status[ncomp].rs_role));
		pjdlog_debug(2, "remote_send[%u]: (%p)   rc: %s", ncomp, hio,
		    nv_get_string(nv, "rc%u", 0));		       
		pjdlog_debug(2, "remote_send[%u]: (%p)   remoteaddr: %s", ncomp, hio,
		    nv_get_string(nv, "remoteaddr%u", 0));
		hio->hio_status[ncomp].rs_state = nv_get_uint8(nv, "state%u", 0);
		pjdlog_debug(2, "remote_send[%u]: (%p)   state: %s", ncomp, hio,
		    state2str(hio->hio_status[ncomp].rs_state));
		
close:
		proto_close(conn);
		if (nv != NULL)
			nv_free(nv);
		pjdlog_debug(2, "remote_send[%u]: (%p) countdown is %d.", ncomp, hio, hio->hio_countdown);		
		if (!refcount_release(&hio->hio_countdown))
			continue;
		pjdlog_debug(2, "remote_send[%u]: (%p) countdown is %d.", ncomp, hio, hio->hio_countdown);		
		pjdlog_debug(2,
		    "remote_send[%u]: (%p) Moving request to the done queue.",
		    ncomp, hio);
		QUEUE_INSERT2(hio, done);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 *  Thread finalizes monitoring operations.
 */
static void *
heartbeat_end_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hast_remote *remote;
	struct hio *hio;
	unsigned int ncomp, ncomps;
	int ret, ii;

	ncomps = res->hr_remote_cnt;

	for (;;) {
		pjdlog_debug(2, "heartbeat_end: Taking request.");
		QUEUE_TAKE2(hio, done);
		pjdlog_debug(2, "heartbeat_end: (%p) Got request.", hio);
		ncomp = 0;		
		if (hio->hio_cmd == HIO_CHECK) {
			mtx_lock(&res->hr_lock);
			TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
				if (hio->hio_status[ncomp].rs_error == 0) {
					remote->r_role = hio->hio_status[ncomp].rs_role;
					remote->r_state = hio->hio_status[ncomp].rs_state;
				} else {
					remote->r_role = HAST_ROLE_UNDEF;
					remote->r_state = HAST_STATE_UNKNOWN;
				}
				ncomp++;
			}
			mtx_unlock(&res->hr_lock);
		}
		pjdlog_debug(2, "heartbeat_end: (%p) Moving request to the free queue.", hio);
		QUEUE_INSERT2(hio, free);
	}
	/* NOTREACHED */
	return (NULL);
}


static void
config_reload(void)
{

}

/*
 * Thread handles signals, etc.
 */
static void *
guard_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hast_remote *remote;
	struct proto_conn *in, *out;
	unsigned int ncomps;
	struct timespec timeout;
	sigset_t mask;
	int signo;

	ncomps = res->hr_remote_cnt;

	PJDLOG_VERIFY(sigemptyset(&mask) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGHUP) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGINT) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGTERM) == 0);

	timeout.tv_nsec = 0;
	signo = -1;

	for (;;) {
		switch (signo) {
		case SIGHUP:
			config_reload();
			break;
		case SIGINT:
		case SIGTERM:
			sigexit_received = true;
			watchdog_exitx(EX_OK,
			    "Termination signal received, exiting.");
			break;
		default:
			break;
		}

		timeout.tv_sec = RETRY_SLEEP;
		signo = sigtimedwait(&mask, NULL, &timeout);
	}
	/* NOTREACHED */
	return (NULL);
}
