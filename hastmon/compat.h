/*-
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
 *
 */

#ifndef _COMPAT_H_
#define _COMPAT_H_

#include <sys/cdefs.h>

#include <sys/types.h>

#ifndef __printflike
/*
 * Taken from FreeBSD's sys/cdefs.h
 */

/*
 * Compiler-dependent macros to declare that functions take printf-like
 * or scanf-like arguments.  They are null except for versions of gcc
 * that are known to support the features properly (old versions of gcc-2
 * didn't permit keeping the keywords out of the application namespace).
 */
#ifndef __GNUC_PREREQ__
#ifdef __GNUC_PREREQ
#define __GNUC_PREREQ__(maj, min)	__GNUC_PREREQ(maj, min)
#else
#define __GNUC_PREREQ__(maj, min) (0)
#endif
#endif
#if !__GNUC_PREREQ__(2, 7) && !defined(__INTEL_COMPILER)
#define	__printflike(fmtarg, firstvararg)
#define	__scanflike(fmtarg, firstvararg)
#define	__format_arg(fmtarg)
#else
#define	__printflike(fmtarg, firstvararg) \
	    __attribute__((__format__ (__printf__, fmtarg, firstvararg)))
#define	__scanflike(fmtarg, firstvararg) \
	    __attribute__((__format__ (__scanf__, fmtarg, firstvararg)))
#define	__format_arg(fmtarg)	__attribute__((__format_arg__ (fmtarg)))
#endif
#endif /* !__printflike */

#ifndef __dead2
#ifdef lint
#define	__dead2
#define __unused
#else
#if !__GNUC_PREREQ__(2, 5) && !defined(__INTEL_COMPILER)
#define	__dead2
#define __unused
#else
#define	__dead2		__attribute__((__noreturn__))
#define __unused	__attribute__((__unused__))
#endif
#endif
#endif /* !__dead2 */

#ifndef __packed
#ifdef lint
#define	__packed
#else
#if !__GNUC_PREREQ__(2, 7) && !defined(__INTEL_COMPILER)
#define	__packed
#else
#define __packed	__attribute__((__packed__))
#endif
#endif
#endif /* !__packed */

#ifndef roundup2
#define roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

/*#if !defined(htole64) && !defined(HAVE_FUNC1_HTOLE64_SYS_TYPES_H)*/
#ifndef htole64
/* XXX: LITTLE_ENDIAN */
#define	htole16(x)	((uint16_t)(x))
#define	htole32(x)	((uint32_t)(x))
#define	htole64(x)	((uint64_t)(x))

#define	le16toh(x)	((uint16_t)(x))
#define	le32toh(x)	((uint32_t)(x))
#define	le64toh(x)	((uint64_t)(x))
#else
#if !defined(le64toh) && defined(letoh64) /* OpenBSD */
#define le16toh		letoh16
#define le32toh		letoh32
#define le64toh		letoh64
#endif
#endif

#ifndef HAVE_FUNC3_STRLCAT_STRING_H
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_FUNC3_STRLCPY_STRING_H
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#if !defined(HAVE_FUNC1_SETPROCTITLE_UNISTD_H) && \
	!defined(HAVE_FUNC1_SETPROCTITLE_STDLIB_H) && \
	!defined(HAVE_FUNC1_SETPROCTITLE_SETPROCTITLE_H)
#ifdef _SETPROCTITLE_USES_ENV
int init_setproctitle(void);
#endif
void setproctitle(const char *fmt, ...);
#endif

#endif /* !_COMPAT_H_ */
