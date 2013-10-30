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

	PJDLOG_ASSERT(res != NULL);
	
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

	PJDLOG_ASSERT(res != NULL);
	
	return complaints_register(res, -1);
}

/*
 * Remove all complaints
 */
void
complaints_clear(struct hast_resource *res)
{
	struct hast_complaint *cmpl;

	PJDLOG_ASSERT(res != NULL);
	
	while ((cmpl = TAILQ_FIRST(&res->hr_complaints)) != NULL) {
		TAILQ_REMOVE(&res->hr_complaints, cmpl, c_next);
		free(cmpl);
	}
}
