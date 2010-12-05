/*-
 * Copyright (c) 2009 The FreeBSD Foundation
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

#include "auth.h"
#include "control.h"
#include "event.h"
#include "hast.h"
#include "hast_proto.h"
#include "hastmon.h"
#include "hooks.h"
#include "proto.h"
#include "pjdlog.h"
#include "subr.h"
#include "synch.h"

struct remote_status {
	int	rs_state;
	int	rs_error;
};

struct hio {
	/* Sequence number */
	uint64_t		hio_seq;
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
	struct remote_status	*hio_remote_status;
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
 * There is one recv list for every component, although local components don't
 * use recv lists as local requests are done synchronously.
 */
static TAILQ_HEAD(, hio) *hio_recv_list;
static pthread_mutex_t *hio_recv_list_lock;
static pthread_cond_t *hio_recv_list_cond;
/*
 * Request is placed on done list by the slowest component (the one that
 * decreased hio_countdown from 1 to 0).
 */
static TAILQ_HEAD(, hio) hio_done_list;
static pthread_mutex_t hio_done_list_lock;
static pthread_cond_t hio_done_list_cond;
/*
 * The lock below allows to synchornize access to remote connections.
 */
static pthread_rwlock_t *hio_remote_lock;

/*
 * Maximum number of outstanding I/O requests.
 */
#define	HAST_HIO_MAX	256

#define	ISCONNECTED(remote, no)	\
	(remote->r_in != NULL && remote->r_out != NULL)

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
static void *remote_recv_thread(void *arg);
static void *local_check_thread(void *arg);
static void *heartbeat_end_thread(void *arg);
static void *guard_thread(void *arg);

static void
cleanup(struct hast_resource *res)
{
	event_send(res, EVENT_STOP);
}

static __dead2 void
primary_exit(int exitcode, const char *fmt, ...)
{
	va_list ap;

	assert(exitcode != EX_OK);
	va_start(ap, fmt);
	pjdlogv_errno(LOG_ERR, fmt, ap);
	va_end(ap);
	cleanup(gres);
	exit(exitcode);
}

static __dead2 void
primary_exitx(int exitcode, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	pjdlogv(exitcode == EX_OK ? LOG_INFO : LOG_ERR, fmt, ap);
	va_end(ap);
	cleanup(gres);
	exit(exitcode);
}

static __dead2 void
primary_reload(void)
{

	pjdlog_info("Terminating due to reload.");
	exit(EX_OK);
}

static bool
real_remote(const struct hast_remote *remote)
{

	return (strcmp(remote->r_addr, "none") != 0);
}

static void
init_environment(struct hast_resource *res)
{
	struct hast_remote *remote;
	struct hio *hio;
	unsigned int ii, ncomps;

	/* Remote components. */
	ncomps = res->hr_remote_cnt;

	/*
	 * Allocate memory needed by lists.
	 */
	hio_send_list = malloc(sizeof(hio_send_list[0]) * ncomps);
	if (hio_send_list == NULL) {
		primary_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for send lists.",
		    sizeof(hio_send_list[0]) * ncomps);
	}
	hio_send_list_lock = malloc(sizeof(hio_send_list_lock[0]) * ncomps);
	if (hio_send_list_lock == NULL) {
		primary_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for send list locks.",
		    sizeof(hio_send_list_lock[0]) * ncomps);
	}
	hio_send_list_cond = malloc(sizeof(hio_send_list_cond[0]) * ncomps);
	if (hio_send_list_cond == NULL) {
		primary_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for send list condition variables.",
		    sizeof(hio_send_list_cond[0]) * ncomps);
	}
	hio_recv_list = malloc(sizeof(hio_recv_list[0]) * ncomps);
	if (hio_recv_list == NULL) {
		primary_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for recv lists.",
		    sizeof(hio_recv_list[0]) * ncomps);
	}
	hio_recv_list_lock = malloc(sizeof(hio_recv_list_lock[0]) * ncomps);
	if (hio_recv_list_lock == NULL) {
		primary_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for recv list locks.",
		    sizeof(hio_recv_list_lock[0]) * ncomps);
	}
	hio_recv_list_cond = malloc(sizeof(hio_recv_list_cond[0]) * ncomps);
	if (hio_recv_list_cond == NULL) {
		primary_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for recv list condition variables.",
		    sizeof(hio_recv_list_cond[0]) * ncomps);
	}
	hio_remote_lock = malloc(sizeof(hio_remote_lock[0]) * res->hr_remote_cnt);
	if (hio_remote_lock == NULL) {
		primary_exitx(EX_TEMPFAIL,
		    "Unable to allocate %zu bytes of memory for remote connections locks.",
		    sizeof(hio_remote_lock[0]) * res->hr_remote_cnt);
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
		TAILQ_INIT(&hio_recv_list[ii]);
		mtx_init(&hio_recv_list_lock[ii]);
		cv_init(&hio_recv_list_cond[ii]);
	}
	for (ii = 0; ii < res->hr_remote_cnt; ii++) {
		rw_init(&hio_remote_lock[ii]);
	}
	TAILQ_INIT(&hio_done_list);
	mtx_init(&hio_done_list_lock);
	cv_init(&hio_done_list_cond);

	/*
	 * Allocate requests pool and initialize requests.
	 */
	for (ii = 0; ii < HAST_HIO_MAX; ii++) {
		hio = malloc(sizeof(*hio));
		if (hio == NULL) {
			primary_exitx(EX_TEMPFAIL,
			    "Unable to allocate %zu bytes of memory for hio request.",
			    sizeof(*hio));
		}
		hio->hio_countdown = 0;
		hio->hio_remote_status = malloc(sizeof(hio->hio_remote_status[0]) *
		    res->hr_remote_cnt);
		if (hio->hio_remote_status == NULL) {
			primary_exitx(EX_TEMPFAIL,
			    "Unable allocate %zu bytes of memory for hio remote status.",
			    sizeof(hio->hio_remote_status[0]) * res->hr_remote_cnt);
		}
		hio->hio_next = malloc(sizeof(hio->hio_next[0]) * ncomps);
		if (hio->hio_next == NULL) {
			primary_exitx(EX_TEMPFAIL,
			    "Unable allocate %zu bytes of memory for hio_next field.",
			    sizeof(hio->hio_next[0]) * ncomps);
		}
		TAILQ_INSERT_HEAD(&hio_free_list, hio, hio_free_next);
	}

	res->hr_local_state = HAST_STATE_UNKNOWN;
	res->hr_local_attempts = 0;
	TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
		remote->r_state = HAST_STATE_UNKNOWN;
	}
}

static void
init_local(struct hast_resource *res)
{
	mtx_init(&res->hr_lock);
}

static bool
init_remote(struct hast_remote *remote, struct proto_conn **inp,
    struct proto_conn **outp)
{
	struct hast_resource *res;
	struct proto_conn *in, *out;
	struct nv *nvout, *nvin;
	const unsigned char *token;
	const char *errmsg;
	size_t size;

	assert((inp == NULL && outp == NULL) || (inp != NULL && outp != NULL));
	assert(real_remote(remote));
	
	in = out = NULL;
	res = remote->r_res;
	
	/* Prepare outgoing connection with remote node. */
	if (proto_client(remote->r_addr, &out) < 0) {
		primary_exit(EX_TEMPFAIL, "Unable to create connection to %s",
		    remote->r_addr);
	}
	/* Try to connect, but accept failure. */
	if (proto_connect(out) < 0) {
		pjdlog_errno(LOG_WARNING, "Unable to connect to %s",
		    remote->r_addr);
		goto close;
	}
	/* Error in setting timeout is not critical, but why should it fail? */
	if (proto_timeout(out, res->hr_timeout) < 0)
		pjdlog_errno(LOG_WARNING, "Unable to set connection timeout");
	/*
	 * First handshake step.
	 * Setup outgoing connection with remote node.
	 */
	nvout = nv_alloc();
	nv_add_string(nvout, res->hr_name, "resource");
	nv_add_int32(nvout, res->hr_priority, "priority");
	auth_add(nvout, out, &res->hr_key);
	if (nv_error(nvout) != 0) {
		pjdlog_common(LOG_WARNING, 0, nv_error(nvout),
		    "Unable to allocate header for connection with %s",
		    remote->r_addr);
		nv_free(nvout);
		goto close;
	}
	if (hast_proto_send(res, out, nvout, NULL, 0) < 0) {
		pjdlog_errno(LOG_WARNING,
		    "Unable to send handshake header to %s",
		    remote->r_addr);
		nv_free(nvout);
		goto close;
	}
	nv_free(nvout);
	if (hast_proto_recv_hdr(out, &nvin) < 0) {
		pjdlog_errno(LOG_WARNING,
		    "Unable to receive handshake header from %s",
		    remote->r_addr);
		goto close;
	}
	errmsg = nv_get_string(nvin, "errmsg");
	if (errmsg != NULL) {
		pjdlog_warning("%s", errmsg);
		/*
		 * The error might be because other end acts as
		 * primary with higher priority. In this case we have
		 * to exit and switch to previous role.
		 */
		if (nv_get_int32(nvin, "priority"))
			primary_exitx(EX_NOPERM,
			    "Primary with higher priority exists.");
	}
	token = nv_get_uint8_array(nvin, &size, "token");
	if (token == NULL) {
		pjdlog_warning("Handshake header from %s has no 'token' field.",
		    remote->r_addr);
		nv_free(nvin);
		goto close;
	}
	if (size != sizeof(remote->r_token)) {
		pjdlog_warning("Handshake header from %s contains 'token' of wrong size (got %zu, expected %zu).",
		    remote->r_addr, size, sizeof(remote->r_token));
		nv_free(nvin);
		goto close;
	}
	bcopy(token, remote->r_token, sizeof(remote->r_token));
	nv_free(nvin);

	/*
	 * Second handshake step.
	 * Setup incoming connection with remote node.
	 */
	if (proto_client(remote->r_addr, &in) < 0) {
		primary_exit(EX_TEMPFAIL, "Unable to create connection to %s",
		    remote->r_addr);
	}
	/* Try to connect, but accept failure. */
	if (proto_connect(in) < 0) {
		pjdlog_errno(LOG_WARNING, "Unable to connect to %s",
		    remote->r_addr);
		goto close;
	}
	/* Error in setting timeout is not critical, but why should it fail? */
	if (proto_timeout(in, res->hr_timeout) < 0)
		pjdlog_errno(LOG_WARNING, "Unable to set connection timeout");
	nvout = nv_alloc();
	auth_add(nvout, in, &res->hr_key);
	nv_add_string(nvout, res->hr_name, "resource");
	nv_add_uint8_array(nvout, remote->r_token, sizeof(remote->r_token),
	    "token");
	nv_add_uint64(nvout, res->hr_resuid, "resuid");
	if (nv_error(nvout) != 0) {
		pjdlog_common(LOG_WARNING, 0, nv_error(nvout),
		    "Unable to allocate header for connection with %s",
		    remote->r_addr);
		nv_free(nvout);
		goto close;
	}
	if (hast_proto_send(res, in, nvout, NULL, 0) < 0) {
		pjdlog_errno(LOG_WARNING,
		    "Unable to send handshake header to %s",
		    remote->r_addr);
		nv_free(nvout);
		goto close;
	}
	nv_free(nvout);
	if (hast_proto_recv_hdr(out, &nvin) < 0) {
		pjdlog_errno(LOG_WARNING,
		    "Unable to receive handshake header from %s",
		    remote->r_addr);
		goto close;
	}
	errmsg = nv_get_string(nvin, "errmsg");
	if (errmsg != NULL) {
		pjdlog_warning("%s", errmsg);
		nv_free(nvin);
		goto close;
	}
	nv_free(nvin);
	pjdlog_info("Connected to %s.", remote->r_addr);
	if (inp != NULL && outp != NULL) {
		*inp = in;
		*outp = out;
	} else {
		remote->r_in = in;
		remote->r_out = out;
	}
	event_send(res, EVENT_CONNECT);
	return (true);
close:
	proto_close(out);
	if (in != NULL)
		proto_close(in);
	return (false);
}

void
hastmon_primary(struct hast_resource *res)
{
	struct hast_remote *remote;
	pthread_t td;
	pid_t pid;
	int error;

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
		pjdlog_exit(EX_TEMPFAIL, "Unable to fork");
	}

	if (pid > 0) {
		/* This is parent. */
		/* Declare that we are receiver. */
		proto_recv(res->hr_event, NULL, 0);
		res->hr_workerpid = pid;
		return;
	}

	gres = res;

	(void)pidfile_close(pfh);
	hook_fini();

	setproctitle("%s (primary)", res->hr_name);

	/* Declare that we are sender. */
	proto_send(res->hr_event, NULL, 0);

	init_local(res);
	init_environment(res);
 	/*
	 * Create the guard thread first, so we can handle signals from the
	 * very begining.
	 */
	error = pthread_create(&td, NULL, guard_thread, res);
	assert(error == 0);
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
	TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
		if(real_remote(remote))
			init_remote(remote, NULL, NULL);
		error = pthread_create(&td, NULL, remote_send_thread, remote);
		assert(error == 0);
		error = pthread_create(&td, NULL, remote_recv_thread, remote);
		assert(error == 0);
	}
	error = pthread_create(&td, NULL, heartbeat_end_thread, res);
	assert(error == 0);
	(void)heartbeat_start_thread(res);
}

static void
reqlog(int loglevel, int debuglevel, const char *fmt, ...)
{
	char msg[1024];
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if ((size_t)len < sizeof(msg)) {
		/* XXX */
	}
	pjdlog_common(loglevel, debuglevel, -1, "%s", msg);
}

static void
remote_close(struct hast_remote *remote, int ncomp)
{
	struct hast_resource *res = remote->r_res;
	
	rw_wlock(&hio_remote_lock[ncomp]);
	/*
	 * A race is possible between dropping rlock and acquiring wlock -
	 * another thread can close connection in-between.
	 */
	if (!ISCONNECTED(remote, ncomp)) {
		assert(remote->r_in == NULL);
		assert(remote->r_out == NULL);
		rw_unlock(&hio_remote_lock[ncomp]);
		return;
	}

	assert(remote->r_in != NULL);
	assert(remote->r_out != NULL);

	pjdlog_debug(2, "Closing incoming connection to %s.",
	    remote->r_addr);
	proto_close(remote->r_in);
	remote->r_in = NULL;
	pjdlog_debug(2, "Closing outgoing connection to %s.",
	    remote->r_addr);
	proto_close(remote->r_out);
	remote->r_out = NULL;

	rw_unlock(&hio_remote_lock[ncomp]);

	pjdlog_warning("Disconnected from %s.", remote->r_addr);

	event_send(res, EVENT_DISCONNECT);
}

/*
 * Threads initiate monitoring operations.
 */
static void *
heartbeat_start_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hio *hio;
	unsigned int ii, ncomps;
	int error;

	/* Number of remote components */
	ncomps = res->hr_remote_cnt;

	for (;;) {
		pjdlog_debug(2, "heartbeat_start: Sending status event to check local state.", hio);
		event_send(res, EVENT_STATUS);
		pjdlog_debug(2, "heartbeat_start: Sleeping for %d sec.", res->hr_heartbeat_interval);
		sleep(res->hr_heartbeat_interval);
		pjdlog_debug(2, "heartbeat_start: Taking free request.");
		QUEUE_TAKE2(hio, free);
		pjdlog_debug(2, "heartbeat_start: (%p) Got free request.", hio);
		for (ii = 0; ii < ncomps; ii++)
			hio->hio_remote_status[ii].rs_error = EINVAL;
		refcount_init(&hio->hio_countdown, ncomps);
		pjdlog_debug(2, "heartbeat_start: (%p) Countdown is %d.", hio, hio->hio_countdown);
		pjdlog_debug(2, "heartbeat_start: (%p) Moving request to the send queues.", hio);
		/* Move request to remote check threads */
		for (ii = 0; ii < ncomps; ii++)
			QUEUE_INSERT1(hio, send, ii);
	}
	/* NOTREACHED */
	return (NULL);
}


/*
 * Thread sends request to secondary node.
 */
static void *
remote_send_thread(void *arg)
{
	struct hast_remote *remote = arg;
	struct hast_resource *res;
	struct hio *hio;
	struct nv *nv;
	unsigned int ncomp;
	bool wakeup;
	uint8_t cmd;
	uint64_t seq;

	res = remote->r_res;
	ncomp = remote->r_ncomp;
	
	for (seq = 1; ; seq++) {
		pjdlog_debug(2, "remote_send[%u]: Taking request.", ncomp);
		QUEUE_TAKE1(hio, send, ncomp);
		pjdlog_debug(2, "remote_send[%u]: (%p) Got request.", ncomp, hio);
		hio->hio_seq = seq;
		nv = nv_alloc();
		cmd = HIO_STATE;
		nv_add_uint8(nv, cmd, "cmd");
		mtx_lock(&res->hr_lock);
		nv_add_uint8(nv, res->hr_local_state, "state");
		mtx_unlock(&res->hr_lock);
		nv_add_uint64(nv, hio->hio_seq, "seq");
		if (nv_error(nv) != 0) {
			hio->hio_remote_status[ncomp].rs_error = nv_error(nv);
			pjdlog_debug(2,
			    "remote_send[%u]: (%p) Unable to prepare header to send.",
			    ncomp, hio);
			reqlog(LOG_ERR, 0, "Unable to prepare header to send (%s): ",
			    strerror(nv_error(nv)));
			/* Move failed request immediately to the done queue. */
			goto done_queue;
		}
		/*
		 * Protect connection from disappearing.
		 */
		rw_rlock(&hio_remote_lock[ncomp]);
		if (!ISCONNECTED(remote, ncomp)) {
			rw_unlock(&hio_remote_lock[ncomp]);
			hio->hio_remote_status[ncomp].rs_error = ENOTCONN;
			goto done_queue;
		}
		/*
		 * Move the request to recv queue before sending it, because
		 * in different order we can get reply before we move request
		 * to recv queue.
		 */
		pjdlog_debug(2,
		    "remote_send[%u]: (%p) Moving request to the recv queue.",
			     ncomp, hio);
		mtx_lock(&hio_recv_list_lock[ncomp]);
		wakeup = TAILQ_EMPTY(&hio_recv_list[ncomp]);
		TAILQ_INSERT_TAIL(&hio_recv_list[ncomp], hio, hio_next[ncomp]);
		mtx_unlock(&hio_recv_list_lock[ncomp]);
		if (hast_proto_send(res, remote->r_out, nv, NULL, 0) < 0) {
			hio->hio_remote_status[ncomp].rs_error = errno;
			rw_unlock(&hio_remote_lock[ncomp]);
			pjdlog_debug(2,
			    "remote_send[%u]: (%p) Unable to send request.",
			    ncomp, hio);
			reqlog(LOG_ERR, 0, "Unable to send request (%s): ",
			    strerror(hio->hio_remote_status[ncomp].rs_error));
			remote_close(remote, ncomp);
			/*
			 * Take request back from the receive queue and move
			 * it immediately to the done queue.
			 */
			mtx_lock(&hio_recv_list_lock[ncomp]);
			TAILQ_REMOVE(&hio_recv_list[ncomp], hio, hio_next[ncomp]);
			mtx_unlock(&hio_recv_list_lock[ncomp]);
			goto done_queue;
		}
		rw_unlock(&hio_remote_lock[ncomp]);
		nv_free(nv);
		if (wakeup)
			cv_signal(&hio_recv_list_cond[ncomp]);
		continue;
done_queue:
		nv_free(nv);
		pjdlog_debug(2, "remote_send[%u]: (%p) countdown is %d.", ncomp,
		    hio, hio->hio_countdown);		
		if (!refcount_release(&hio->hio_countdown))
			continue;
		pjdlog_debug(2, "remote_send[%u]: (%p) countdown is %d.", ncomp,
		    hio, hio->hio_countdown);		
		pjdlog_debug(2,
		    "remote_send[%u]: (%p) Moving request to the done queue.",
		    ncomp, hio);
		QUEUE_INSERT2(hio, done);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Thread receives answer from secondary node.
 */
static void *
remote_recv_thread(void *arg)
{
	struct hast_remote *remote = arg;
	struct hast_resource *res;
	struct hio *hio;
	struct nv *nv;
	unsigned int ncomp;
	uint64_t seq;
	int error;

	res = remote->r_res;
	ncomp = remote->r_ncomp;

	for (;;) {
		/* Wait until there is anything to receive. */
		pjdlog_debug(2, "remote_recv[%u]: Waiting request.", ncomp);
		mtx_lock(&hio_recv_list_lock[ncomp]);
		while (TAILQ_EMPTY(&hio_recv_list[ncomp])) {
			pjdlog_debug(2, "remote_recv[%u]: No requests, waiting.",
			    ncomp);
			cv_wait(&hio_recv_list_cond[ncomp],
			    &hio_recv_list_lock[ncomp]);
		}
		mtx_unlock(&hio_recv_list_lock[ncomp]);
		pjdlog_debug(2, "remote_recv[%u]: There is something to receive.",
		    ncomp);
		rw_rlock(&hio_remote_lock[ncomp]);
		if (!ISCONNECTED(remote, ncomp)) {
			rw_unlock(&hio_remote_lock[ncomp]);
			/*
			 * Connection is dead, so move all pending requests to
			 * the done queue (one-by-one).
			 */
			mtx_lock(&hio_recv_list_lock[ncomp]);
			hio = TAILQ_FIRST(&hio_recv_list[ncomp]);
			assert(hio != NULL);
			TAILQ_REMOVE(&hio_recv_list[ncomp], hio,
			    hio_next[ncomp]);
			mtx_unlock(&hio_recv_list_lock[ncomp]);
			goto done_queue;
		}
		if (hast_proto_recv_hdr(remote->r_in, &nv) < 0) {
			pjdlog_errno(LOG_ERR,
			    "Unable to receive reply header");
			rw_unlock(&hio_remote_lock[ncomp]);
			remote_close(remote, ncomp);
			continue;
		}
		rw_unlock(&hio_remote_lock[ncomp]);
		pjdlog_debug(2, "remote_recv[%u]: Got reply header.", ncomp);
		seq = nv_get_uint64(nv, "seq");
		if (seq == 0) {
			pjdlog_error("Header contains no 'seq' field.");
			nv_free(nv);
			continue;
		}
		mtx_lock(&hio_recv_list_lock[ncomp]);
		TAILQ_FOREACH(hio, &hio_recv_list[ncomp], hio_next[ncomp]) {
			if (hio->hio_seq == seq) {
				TAILQ_REMOVE(&hio_recv_list[ncomp], hio,
				    hio_next[ncomp]);
				break;
			}
		}
		mtx_unlock(&hio_recv_list_lock[ncomp]);		
		if (hio == NULL) {
			pjdlog_error("Found no request matching received 'seq' field (%ju).",
			    (uintmax_t)seq);
			nv_free(nv);
			continue;
		}
		pjdlog_debug(2,
		    "remote_recv[%u]: Found request (%p) matching received 'seq' field (%ju).",
		    ncomp, hio, (uintmax_t)seq);
		error = nv_get_int16(nv, "error");
		if (error != 0) {
			/* Request failed on remote side. */
			hio->hio_remote_status[ncomp].rs_error = 0;
			nv_free(nv);
			goto done_queue;
		}
		hio->hio_remote_status[ncomp].rs_state = nv_get_uint8(nv, "state");
		pjdlog_debug(2, "remote_recv[%u]: Remote state is %s (%d)",
		    ncomp, state2str(hio->hio_remote_status[ncomp].rs_state),
		    hio->hio_remote_status[ncomp].rs_state);
		hio->hio_remote_status[ncomp].rs_error = 0;
		nv_free(nv);
done_queue:
		if (refcount_release(&hio->hio_countdown)) {
			pjdlog_debug(2,
			    "remote_recv[%u]: (%p) Moving request to the done queue.",
			    ncomp, hio);
			QUEUE_INSERT2(hio, done);
		}
		pjdlog_debug(2,
		    "remote_recv[%u]: (%p) countdown is %d.",
		    ncomp, hio, hio->hio_countdown);		
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 *  Thread completes monitoring operations.
 */
static void *
heartbeat_end_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hast_remote *remote;
	struct hio *hio;
	int ret;
	char *remote_run;

	for (;;) {
		pjdlog_debug(2, "heartbeat_end: Taking request.");
		QUEUE_TAKE2(hio, done);
		pjdlog_debug(2, "heartbeat_end: (%p) Got request.", hio);
		/*
		 * Get nodes' status from hio.
		 */
		/* XXX: rs_error is ignored for now */
		mtx_lock(&res->hr_lock);
		remote_run = NULL;
		TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
			remote->r_state =
				hio->hio_remote_status[remote->r_ncomp].rs_state;
			if (remote->r_state == HAST_STATE_RUN ||
			    remote->r_state == HAST_STATE_STARTING)
				remote_run = remote->r_addr;
		}
		mtx_unlock(&res->hr_lock);
		/*
		 * Check the resource state and try to restart the
		 * resource if necessary.
		 */
		if (remote_run == NULL) {
			mtx_lock(&res->hr_lock);
			switch(res->hr_local_state) {
			case HAST_STATE_RUN:
				pjdlog_debug(2,
					     "heartbeat_end: (%p) Resource state is OK.",
					     hio);
				res->hr_local_attempts = 0;
				break;
			case HAST_STATE_STOPPED:
			case HAST_STATE_UNKNOWN:
				res->hr_local_attempts++;
				if (res->hr_local_attempts > res->hr_local_attempts_max) {					
					pjdlog_debug(2,
					    "heartbeat_end: (%p) Resource is %s and exceeded max start attempts %d.",
					    hio, state2str(res->hr_local_state), res->hr_local_attempts_max);
					mtx_unlock(&res->hr_lock);
					primary_exitx(EX_UNAVAILABLE, "Unable to start service after %d attempts",
					    res->hr_local_attempts);
					/* NOTREACHED */
					break;
				}
				pjdlog_debug(2,
				    "heartbeat_end: (%p) Resource is %s. Starting (attempt %d).",
				    hio, state2str(res->hr_local_state), res->hr_local_attempts);
				mtx_unlock(&res->hr_lock);
				event_send(res, EVENT_START);
				mtx_lock(&res->hr_lock);
				pjdlog_debug(2,
				    "heartbeat_end: (%p) setting hr_local_state to '%s'.",
				    hio, state2str(HAST_STATE_STARTING));
				res->hr_local_state = HAST_STATE_STARTING;
				break;
			case HAST_STATE_STARTING:
				break;
			default:
				assert(!"Wrong state.");
			}
			mtx_unlock(&res->hr_lock);
		} else {
			pjdlog_error("heartbeat_end: (%p) Resource on secondary %s is not STOPPED.",
			    hio, remote_run);
			if (res->hr_local_state == HAST_STATE_RUN) {
				pjdlog_debug(1, "heartbeat_end: (%p) Stopping resource.", hio);
				event_send(res, EVENT_STOP);
				mtx_lock(&res->hr_lock);				
				res->hr_local_state = HAST_STATE_STOPPING;
				mtx_unlock(&res->hr_lock);
			}
		}
		pjdlog_debug(2, "heartbeat_end: (%p) Moving request to the free queue.", hio);
		QUEUE_INSERT2(hio, free);
	}
	/* NOTREACHED */
	return (NULL);
}

static void
guard_one(struct hast_remote *remote)
{
	struct proto_conn *in, *out;

	rw_rlock(&hio_remote_lock[remote->r_ncomp]);

	if (!real_remote(remote)) {
		rw_unlock(&hio_remote_lock[remote->r_ncomp]);
		return;
	}

	if (ISCONNECTED(remote, remote->r_ncomp)) {
		assert(remote->r_in != NULL);
		assert(remote->r_out != NULL);
		rw_unlock(&hio_remote_lock[remote->r_ncomp]);
		pjdlog_debug(2, "remote_guard: Connection to %s is ok.",
		    remote->r_addr);
		return;
	}

	assert(remote->r_in == NULL);
	assert(remote->r_out == NULL);
	/*
	 * Upgrade the lock. It doesn't have to be atomic as no other thread
	 * can change connection status from disconnected to connected.
	 */
	rw_unlock(&hio_remote_lock[remote->r_ncomp]);
	pjdlog_debug(2, "remote_guard: Reconnecting to %s.",
	    remote->r_addr);
	in = out = NULL;
	if (init_remote(remote, &in, &out)) {
		rw_wlock(&hio_remote_lock[remote->r_ncomp]);
		assert(remote->r_in == NULL);
		assert(remote->r_out == NULL);
		assert(in != NULL && out != NULL);
		remote->r_in = in;
		remote->r_out = out;
		rw_unlock(&hio_remote_lock[remote->r_ncomp]);
		pjdlog_info("Successfully reconnected to %s.",
		    remote->r_addr);
	} else {
		/* Both connections should be NULL. */
		assert(remote->r_in == NULL);
		assert(remote->r_out == NULL);
		assert(in == NULL && out == NULL);
		pjdlog_debug(2, "remote_guard: Reconnect to %s failed.",
		    remote->r_addr);
	}
}

/*
 * Thread guards remote connections and reconnects when needed, handles
 * signals, etc.
 */
static void *
guard_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hast_remote *remote;
	struct proto_conn *in, *out;
	unsigned int ncomps;
	struct timespec timeout;
	time_t lastcheck, now;
	sigset_t mask;
	int signo;

	ncomps = res->hr_remote_cnt;
	lastcheck = time(NULL);

	PJDLOG_VERIFY(sigemptyset(&mask) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGHUP) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGINT) == 0);
	PJDLOG_VERIFY(sigaddset(&mask, SIGTERM) == 0);

	timeout.tv_sec = res->hr_heartbeat_interval;
	timeout.tv_nsec = 0;
	signo = -1;

	for (;;) {
		switch (signo) {
		case SIGHUP:
			primary_reload();
			break;
		case SIGINT:
		case SIGTERM:
			sigexit_received = true;
			primary_exitx(EX_OK,
			    "Termination signal received, exiting.");
			break;
		default:
			break;
		}

		pjdlog_debug(2, "remote_guard: Checking connections.");
		now = time(NULL);
		if (lastcheck + res->hr_heartbeat_interval <= now) {
			TAILQ_FOREACH(remote, &res->hr_remote, r_next)
				guard_one(remote);
			lastcheck = now;
		}
		signo = sigtimedwait(&mask, NULL, &timeout);
	}
	/* NOTREACHED */
	return (NULL);
}
