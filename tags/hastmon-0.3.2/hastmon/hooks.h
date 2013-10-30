/*-
 * Copyright (c) 2010 The FreeBSD Foundation
 * Copyright (c) 2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
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
 *
 * $FreeBSD$
 */

#ifndef	_HOOKS_H_
#define	_HOOKS_H_

#include <sys/types.h>

#include <stdarg.h>
#include <stdbool.h>

#include "hast.h"

#define	HOOKCALLER_MAGIC	0x80190ca
struct hook_caller {
	/* Magic. */
	int	hc_magic;
	/* Resource. */
	struct hast_resource *hc_res;
	/* Event the hook was generated on. */
	int	hc_event;
};

struct hook_caller* hook_caller_alloc(struct hast_resource *res, int event);
void hook_caller_free(struct hook_caller *coller);
void hook_invalidate_callers(struct hast_resource *res);

void hook_init(void);
void hook_fini(void);
void hook_check_one(pid_t pid, int status);
void hook_check(void);
void hook_exec(struct hook_caller *caller, const char *path, ...);
void hook_execv(struct hook_caller *caller, const char *path, va_list ap);

#endif	/* !_HOOKS_H_ */
