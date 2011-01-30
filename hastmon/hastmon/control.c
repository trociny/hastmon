/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
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
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hast.h"
#include "event.h"
#include "hastmon.h"
#include "hast_proto.h"
#include "hooks.h"
#include "nv.h"
#include "pjdlog.h"
#include "proto.h"
#include "synch.h"
#include "subr.h"

#include "control.h"

void
child_cleanup(struct hast_resource *res)
{

	/* We don't want send event status to dead worker.*/
	hook_invalidate_callers(res);
	
	proto_close(res->hr_ctrl);
	res->hr_ctrl = NULL;
	if (res->hr_event != NULL) {
		proto_close(res->hr_event);
		res->hr_event = NULL;
	}
	res->hr_workerpid = 0;
}

static void
control_set_role_common(struct hastmon_config *cfg, struct nv *nvout,
    uint8_t role, struct hast_resource *res, const char *name, unsigned int no)
{
	int oldrole;

	/* Name is always needed. */
	if (name != NULL)
		nv_add_string(nvout, name, "resource%u", no);

	if (res == NULL) {
		assert(cfg != NULL);
		assert(name != NULL);

		TAILQ_FOREACH(res, &cfg->hc_resources, hr_next) {
			if (strcmp(res->hr_name, name) == 0)
				break;
		}
		if (res == NULL) {
			nv_add_int16(nvout, EHAST_NOENTRY, "error%u", no);
			return;
		}
	}
	assert(res != NULL);

	/* Send previous role back. */
	nv_add_string(nvout, role2str(res->hr_role), "role%u", no);

	/* Nothing changed, return here. */
	if (role == res->hr_role)
		return;

	pjdlog_prefix_set("[%s] (%s) ", res->hr_name, role2str(res->hr_role));
	pjdlog_info("Role changed to %s.", role2str(role));

	/* Change role to the new one. */
	oldrole = res->hr_role;
	res->hr_role = role;
	pjdlog_prefix_set("[%s] (%s) ", res->hr_name, role2str(res->hr_role));

	/*
	 * If previous role was primary, secondary or watchdog we have
	 * to kill process doing that work.
	 */
	if (res->hr_workerpid != 0)
		terminate_worker(res, SIGTERM);

	/* Start worker process if we are changing to primary. */
	if (role == HAST_ROLE_PRIMARY)
		hastmon_primary(res);
	/* Start worker process if we are changing to watchdog. */
	if (role == HAST_ROLE_WATCHDOG)
		hastmon_watchdog(res);
	pjdlog_prefix_set("%s", "");
	hook_exec(NULL, res->hr_exec, "role", res->hr_name, role2str(oldrole),
	    role2str(res->hr_role), NULL);
}

void
control_set_role(struct hast_resource *res, uint8_t role)
{

	control_set_role_common(NULL, NULL, role, res, NULL, 0);
}

static void
control_status_worker(struct hast_resource *res, struct nv *nvout,
    unsigned int no)
{
	struct nv *cnvin, *cnvout;
	struct hast_remote *remote;
	const char *str;
	int error;

	cnvin = cnvout = NULL;
	error = 0;

	/*
	 * Prepare and send command to worker process.
	 */
	cnvout = nv_alloc();
	nv_add_uint8(cnvout, HASTCTL_STATUS, "cmd");
	error = nv_error(cnvout);
	if (error != 0) {
		pjdlog_common(LOG_ERR, 0, error,
		    "Unable to prepare control header");
		goto end;
	}
	if (hast_proto_send(res, res->hr_ctrl, cnvout, NULL, 0) < 0) {
		error = errno;
		pjdlog_errno(LOG_ERR, "Unable to send control header");
		goto end;
	}

	/*
	 * Receive response.
	 */
	if (hast_proto_recv_hdr(res->hr_ctrl, &cnvin) < 0) {
		error = errno;
		pjdlog_errno(LOG_ERR, "Unable to receive control header");
		goto end;
	}

	error = nv_get_int16(cnvin, "error");
	if (error != 0)
		goto end;

	TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
		if ((str = nv_get_string(cnvin, "remotestate%u", remote->r_ncomp)) == NULL) {
			error = ENOENT;
			pjdlog_debug(2, "control_status_worker: Cant' get remotestate%u",
			    remote->r_ncomp);
			goto end;
		}
		nv_add_string(nvout, str, "remotestate%u.%u", no, remote->r_ncomp);
		if (res->hr_role == HAST_ROLE_WATCHDOG) {
			if ((str = nv_get_string(cnvin, "remoterole%u",
				    remote->r_ncomp)) == NULL) {
				error = ENOENT;
				pjdlog_debug(2, "control_status_worker: Cant' get remoterole%u",
				    remote->r_ncomp);
				goto end;
			}
			nv_add_string(nvout, str, "remoterole%u.%u", no, remote->r_ncomp);			
		}
	}
	nv_add_uint8(nvout, nv_get_uint8(cnvin, "state"), "state%u", no);
	nv_add_int32(nvout, nv_get_uint8(cnvin, "attempts"), "attempts%u", no);

end:
	if (cnvin != NULL)
		nv_free(cnvin);
	if (cnvout != NULL)
		nv_free(cnvout);
	if (error != 0)
		nv_add_int16(nvout, error, "error");
}

static void
control_status(struct hastmon_config *cfg, struct nv *nvout,
    struct hast_resource *res, const char *name, unsigned int no)
{
	struct hast_remote *remote;
	int cnt;

	assert(cfg != NULL);
	assert(nvout != NULL);
	assert(name != NULL);

	/* Name is always needed. */
	nv_add_string(nvout, name, "resource%u", no);

	if (res == NULL) {
		TAILQ_FOREACH(res, &cfg->hc_resources, hr_next) {
			if (strcmp(res->hr_name, name) == 0)
				break;
		}
		if (res == NULL) {
			nv_add_int16(nvout, EHAST_NOENTRY, "error%u", no);
			return;
		}
	}
	assert(res != NULL);
	nv_add_string(nvout, res->hr_exec, "exec%u", no);
	nv_add_int32(nvout, res->hr_local_attempts_max, "attempts_max%u", no);
	TAILQ_FOREACH(remote, &res->hr_remote, r_next) {
		nv_add_string(nvout, remote->r_addr, "remoteaddr%u.%u",
		    no, remote->r_ncomp);
	}
	nv_add_uint8(nvout, res->hr_role, "role%u", no);
	cnt = complaints_cnt(res);
	nv_add_int32(nvout, cnt, "complaints%u", no);
	nv_add_int32(nvout, res->hr_complaint_critical_cnt,
	    "complaints_critical%u", no);
	nv_add_int32(nvout, res->hr_complaint_interval,
	    "complaints_interval%u", no);
	nv_add_int32(nvout, res->hr_heartbeat_interval,
	    "heartbeat%u", no);

	switch (res->hr_role) {
	case HAST_ROLE_WATCHDOG:
	case HAST_ROLE_PRIMARY:
		assert(res->hr_workerpid != 0);
		/* FALLTHROUGH */
	case HAST_ROLE_SECONDARY:
		if (res->hr_workerpid != 0)
			break;
		/* FALLTHROUGH */
	default:
		return;
	}

	/*
	 * If we are here, it means that we have a worker process, which we
	 * want to ask some questions.
	 */
	control_status_worker(res, nvout, no);
}

void
control_handle(struct hastmon_config *cfg)
{
	struct proto_conn *conn;
	struct nv *nvin;

	if (proto_accept(cfg->hc_controlconn, &conn) < 0) {
		pjdlog_errno(LOG_ERR, "Unable to accept control connection");
		return;
	}

	cfg->hc_controlin = conn;
	nvin = NULL;

	if (hast_proto_recv_hdr(conn, &nvin) < 0) {
		pjdlog_errno(LOG_ERR, "Unable to receive control header");
		nvin = NULL;
		goto close;
	}

	control_handle_common(cfg, conn, nvin, false);

close:
	if (nvin != NULL)
		nv_free(nvin);
	proto_close(conn);
	cfg->hc_controlin = NULL;
}

bool
control_auth_confirm(struct hastmon_config *cfg, struct nv *nv,
    struct proto_conn *conn, const char *str)
{
	struct hast_resource *res;
	const char *name;
	unsigned int ii;
	
	assert(cfg != NULL);
	assert(nv != NULL);
	assert(conn != NULL);
	assert(str != NULL);
	
	if (strcmp(str, "all") == 0) {
		
		/* All configured resources. */
		
		TAILQ_FOREACH(res, &cfg->hc_resources, hr_next) {
			if (!auth_confirm(nv, conn, &res->hr_key))
				return false;
		}
	} else {
		/* Only selected resources. */
		
		for (ii = 0; ; ii++) {
			name = nv_get_string(nv, "resource%u", ii);
			if (name == NULL)
				break;
			TAILQ_FOREACH(res, &cfg->hc_resources, hr_next) {
				if (strcmp(res->hr_name, name) == 0)
					if (!auth_confirm(nv, conn, &res->hr_key))
						return false;
					else
						break;
			}
			if (res == NULL)
				return false;
		}
	}
	return true;
}

void
control_handle_common(struct hastmon_config *cfg, struct proto_conn *conn,
    struct nv *nvin, bool auth)
{

	struct nv *nvout;
	unsigned int ii;
	const char *str;
	uint8_t cmd, role;
	int error;

	nvout = NULL;
	role = HAST_ROLE_UNDEF;
	
	/* Obtain command code. 0 means that nv_get_uint8() failed. */
	cmd = nv_get_uint8(nvin, "cmd");
	if (cmd == 0) {
		pjdlog_error("Control header is missing 'cmd' field.");
		error = EHAST_INVALID;
		goto close;
	}
	/* Allocate outgoing nv structure. */
	nvout = nv_alloc();
	if (nvout == NULL) {
		pjdlog_error("Unable to allocate header for control response.");
		error = EHAST_NOMEMORY;
		goto close;
	}

	error = 0;

	str = nv_get_string(nvin, "resource0");
	if (str == NULL) {
		pjdlog_error("Control header is missing 'resource0' field.");
		error = EHAST_INVALID;
		goto fail;
	}
	if (auth && !control_auth_confirm(cfg, nvin, conn, str)) {
		pjdlog_error("Authentication failed.");
		error = EHAST_AUTHFAILED;
		goto close;
	}	
	if (cmd == HASTCTL_SET_ROLE) {
		role = nv_get_uint8(nvin, "role");
		switch (role) {
		case HAST_ROLE_INIT:	/* Is that valid to set, hmm? */
		case HAST_ROLE_PRIMARY:
		case HAST_ROLE_SECONDARY:
		case HAST_ROLE_WATCHDOG:
			break;
		default:
			pjdlog_error("Invalid role received (%hhu).", role);
			error = EHAST_INVALID;
			goto fail;
		}
	}
	if (strcmp(str, "all") == 0) {
		struct hast_resource *res;

		/* All configured resources. */

		ii = 0;
		TAILQ_FOREACH(res, &cfg->hc_resources, hr_next) {
			switch (cmd) {
			case HASTCTL_SET_ROLE:
				control_set_role_common(cfg, nvout, role, res,
				    res->hr_name, ii++);
				break;
			case HASTCTL_STATUS:
				control_status(cfg, nvout, res, res->hr_name,
				    ii++);
				break;
			default:
				pjdlog_error("Invalid command received (%hhu).",
				    cmd);
				error = EHAST_UNIMPLEMENTED;
				goto fail;
			}
		}
	} else {
		/* Only selected resources. */

		for (ii = 0; ; ii++) {
			str = nv_get_string(nvin, "resource%u", ii);
			if (str == NULL)
				break;
			switch (cmd) {
			case HASTCTL_SET_ROLE:
				control_set_role_common(cfg, nvout, role, NULL,
				    str, ii);
				break;
			case HASTCTL_STATUS:
				control_status(cfg, nvout, NULL, str, ii);
				break;
			default:
				pjdlog_error("Invalid command received (%hhu).",
				    cmd);
				error = EHAST_UNIMPLEMENTED;
				goto fail;
			}
		}
	}
	if (nv_error(nvout) != 0)
		goto close;
fail:
	if (error != 0)
		nv_add_int16(nvout, error, "error");

	if (hast_proto_send(NULL, conn, nvout, NULL, 0) < 0)
		pjdlog_errno(LOG_ERR, "Unable to send control response");
close:
	if (nvout != NULL)
		nv_free(nvout);
}

/*
 * Thread sends notifications to a child about status of action
 * (e.g. hook) that was previously started on an event sent by the
 * child.
 */
void *
control_send_event_status(struct hast_resource *res, int event, int status)
{
	struct nv *cnvout;
	int error;

	assert(res != NULL);
	assert(event >= EVENT_MIN && event <= EVENT_MAX);

	cnvout = NULL;

	/*
	 * Prepare and send status to child process.
	 */
	if (res->hr_ctrl == NULL) {
		pjdlog_debug(2, "No connection with child. Ignoring event status.");
		goto done;
	}
	cnvout = nv_alloc();
	nv_add_uint8(cnvout, HASTCTL_EVENT_STATUS, "cmd");
	nv_add_uint8(cnvout, (uint8_t)event, "event");
	nv_add_uint8(cnvout, (uint8_t)status, "status");	
	error = nv_error(cnvout);
	if (error != 0) {
		pjdlog_common(LOG_ERR, 0, error,
		    "Unable to prepare event status header");
		goto done;
	}
	if (hast_proto_send(res, res->hr_ctrl, cnvout, NULL, 0) < 0) {
		pjdlog_errno(LOG_ERR, "Unable to send event status header");
		goto done;
	}
done:
	if (cnvout != NULL)
		nv_free(cnvout);
}

/*
 * Thread handles control requests from the parent.
 */
void *
ctrl_thread(void *arg)
{
	struct hast_resource *res = arg;
	struct hast_remote *remote;
	struct nv *nvin, *nvout;
	uint8_t cmd, event, status;

	for (;;) {
		if (hast_proto_recv_hdr(res->hr_ctrl, &nvin) < 0) {
			if (sigexit_received)
				pthread_exit(NULL);
			pjdlog_errno(LOG_ERR,
			    "Unable to receive control message");
			kill(getpid(), SIGTERM);
			pthread_exit(NULL);
		}
		pjdlog_debug(2, "ctrl_thread: Control message received.");
		cmd = nv_get_uint8(nvin, "cmd");
		if (cmd == 0) {
			pjdlog_error("Control message is missing 'cmd' field.");
			nv_free(nvin);
			continue;
		}
		nvout = NULL;
		switch (cmd) {
		case HASTCTL_STATUS:
			pjdlog_debug(2, "ctrl_thread: Control message cmd: status.");
			nvout = nv_alloc();
			synch_mtx_lock(&res->hr_lock);
			TAILQ_FOREACH(remote, &res->hr_remote, r_next)
				switch (res->hr_role) {
				case HAST_ROLE_PRIMARY:
				case HAST_ROLE_SECONDARY:
					if (remote->r_in == NULL ||
					    remote->r_out == NULL)
						nv_add_string(nvout, "disconnected",
						    "remotestate%u", remote->r_ncomp);
					else
						nv_add_string(nvout, "connected",
						    "remotestate%u", remote->r_ncomp);
					break;
				case HAST_ROLE_WATCHDOG:
					nv_add_string(nvout, state2str(remote->r_state),
					    "remotestate%u", remote->r_ncomp);
					nv_add_string(nvout, role2str(remote->r_role),
					    "remoterole%u", remote->r_ncomp);
					break;
				default:
					assert(!"invalid role");
					break;
				}
			nv_add_uint8(nvout, res->hr_local_state, "state");
			nv_add_uint8(nvout, res->hr_local_attempts, "attempts");
			synch_mtx_unlock(&res->hr_lock);
			if (nv_error(nvout) != 0) {
				pjdlog_error("Unable to create answer on control message.");
				goto nv_free;
			}
			if (hast_proto_send(NULL, res->hr_ctrl, nvout, NULL, 0) < 0) {
				pjdlog_errno(LOG_ERR,
				    "Unable to send reply to control message");
			}
			break;
		case HASTCTL_EVENT_STATUS:
			pjdlog_debug(2, "ctrl_thread: Control message cmd: event.");
			event = nv_get_uint8(nvin, "event");
			status = nv_get_uint8(nvin, "status");
			switch (event) {
			case EVENT_STATUS:				
				pjdlog_debug(2,"ctrl_thread: status event received with status %u.",
				    (unsigned int)status);
				synch_mtx_lock(&res->hr_lock);
				switch (status) {
				case 0:
					res->hr_local_state = HAST_STATE_RUN;
					break;
				case 1:
					res->hr_local_state = HAST_STATE_STOPPED;
					break;
				default:
					res->hr_local_state = HAST_STATE_UNKNOWN;
					break;
				}
				synch_mtx_unlock(&res->hr_lock);
			default:
				break;
			}
			break;
		default:
			break;
		}
	nv_free:
		nv_free(nvin);
		if (nvout != NULL)
			nv_free(nvout);
	}
	/* NOTREACHED */
	return (NULL);
}
