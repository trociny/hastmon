/*-
 * Copyright (c) 2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * Copyright (c) 2010 Mikolaj Golub <to.my.trociny@gmail.com>
 * All rights reserved.
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

#include <errno.h>

#include "hast.h"
#include "hast_proto.h"
#include "hooks.h"
#include "nv.h"
#include "pjdlog.h"
#include "proto.h"
#include "subr.h"

#include "event.h"

void
event_send(struct hast_resource *res, int event)
{
	struct nv *nvin, *nvout;
	int error;

	PJDLOG_ASSERT(res != NULL);
	PJDLOG_ASSERT(event >= EVENT_MIN && event <= EVENT_MAX);

	nvin = nvout = NULL;

	/*
	 * Prepare and send event to parent process.
	 */
	nvout = nv_alloc();
	nv_add_uint8(nvout, (uint8_t)event, "event");
	error = nv_error(nvout);
	if (error != 0) {
		pjdlog_common(LOG_ERR, 0, error,
		    "Unable to prepare event header");
		goto done;
	}
	if (hast_proto_send(res, res->hr_event, nvout, NULL, 0) < 0) {
		pjdlog_errno(LOG_ERR, "Unable to send event header");
		goto done;
	}
	if (hast_proto_recv_hdr(res->hr_event, &nvin) < 0) {
		pjdlog_errno(LOG_ERR, "Unable to receive event header");
		goto done;
	}
	/*
	 * Do nothing with the answer. We only wait for it to be sure not
	 * to exit too quickly after sending an event and exiting immediately.
	 */
done:
	if (nvin != NULL)
		nv_free(nvin);
	if (nvout != NULL)
		nv_free(nvout);
}

int
event_recv(struct hast_resource *res)
{
	struct nv *nvin, *nvout;
	const char *evstr;
	uint8_t event;
	struct hook_caller *caller;
	int error;

	PJDLOG_ASSERT(res != NULL);

	nvin = nvout = NULL;

	if (hast_proto_recv_hdr(res->hr_event, &nvin) < 0) {
		/*
		 * First error log as debug. This is because worker process
		 * most likely exited.
		 */
		pjdlog_common(LOG_DEBUG, 1, errno,
		    "Unable to receive event header");
		goto fail;
	}

	event = nv_get_uint8(nvin, "event");
	if (event == EVENT_NONE) {
		pjdlog_error("Event header is missing 'event' field.");
		goto fail;
	}

	switch (event) {
	case EVENT_CONNECT:
		evstr = "connect";
		break;
	case EVENT_DISCONNECT:
		evstr = "disconnect";
		break;
	case EVENT_START:
		evstr = "start";
		break;
	case EVENT_STOP:
		evstr = "stop";
		break;
	case EVENT_STATUS:
		evstr = "status";
		break;
	case EVENT_COMPLAINT:
		evstr = "complain";
		complaints_add(res);
		break;
	default:
		pjdlog_error("Event header contain invalid event number (%hhu).",
		    event);
		goto fail;
	}
	caller = hook_caller_alloc(res, event);
	if (caller == NULL) {
		pjdlog_common(LOG_ERR, 0, error,
			      "Unable to allocate memory for caller.");
		goto fail;
	}
	pjdlog_prefix_set("[%s] (%s) ", res->hr_name, role2str(res->hr_role));
	hook_exec(caller, res->hr_exec, evstr, res->hr_name, NULL);
	pjdlog_prefix_set("%s", "");

	nvout = nv_alloc();
	nv_add_int16(nvout, 0, "error");
	error = nv_error(nvout);
	if (error != 0) {
		pjdlog_common(LOG_ERR, 0, error,
		    "Unable to prepare event header");
		goto fail;
	}
	if (hast_proto_send(res, res->hr_event, nvout, NULL, 0) < 0) {
		pjdlog_errno(LOG_ERR, "Unable to send event header");
		goto fail;
	}
	nv_free(nvin);
	nv_free(nvout);
	return (0);
fail:
	if (nvin != NULL)
		nv_free(nvin);
	if (nvout != NULL)
		nv_free(nvout);
	return (-1);
}
