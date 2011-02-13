/*-
 * Copyright (C) 2011 Mikolaj Golub
 * Copyright (C) 2002-2010 Igor Sysoev
 *
 * Based on setproctitle from NGINX project.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
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

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * To change the process title in Linux we have to set argv[1]
 * to NULL and to copy the title to the same place where the argv[0] points to.
 * However, argv[0] may be too small to hold a new title.  Fortunately, Linux
 * stores argv[] and environ[] one after another.  So we should
 * ensure that is the continuous memory and then we allocate the new memory
 * for environ[] and copy it.  After this we could use the memory starting
 * from argv[0] for our process title.
 */

#ifdef _SETPROCTITLE_USES_ENV

extern char **hast_environ;
extern char **hast_argv;

static char *hast_argv_last;

int
init_setproctitle(void)
{
    u_char		*p;
    size_t		size;
    unsigned int	i;

    size = 0;

    for (i = 0; hast_environ[i]; i++) {
	    size += strlen(hast_environ[i]) + 1;
    }

    p = malloc(size);
    if (p == NULL) {
        return -1;
    }

    hast_argv_last = hast_argv[0];

    for (i = 0; hast_argv[i] != NULL; i++) {
        if (hast_argv_last == hast_argv[i]) {
            hast_argv_last = hast_argv[i] + strlen(hast_argv[i]) + 1;
        }
    }

    for (i = 0; hast_environ[i] != NULL; i++) {
        if (hast_argv_last == hast_environ[i]) {

            size = strlen(hast_environ[i]) + 1;
            hast_argv_last = hast_environ[i] + size;

            strncpy(p, (u_char *) hast_environ[i], size);
            hast_environ[i] = (char *) p;
            p += size;
        }
    }

    hast_argv_last--;

    return 0;
}


void
setproctitle(const char *fmt, ...)
{
	char		*p;
	char		title[PATH_MAX];
	char		fmt_[PATH_MAX];	
	size_t		len;
	va_list		ap;

	assert(hast_argv_last != NULL);
	
	p = hast_argv[0];
	len = strlen(hast_argv[0]);
	if (len > 0) {
		p += len - 1;
		while ((p != hast_argv[0]) && (*p != '/'))
			p--;
		p++;
	}
	
	snprintf(fmt_, sizeof(fmt_), "%s: %s", p, fmt);
	fmt = fmt_;

	va_start(ap, fmt);
	vsnprintf(title, sizeof(title), fmt, ap);
	va_end(ap);
	
	hast_argv[1] = NULL;

	(void)strncpy(hast_argv[0], (u_char *) title, hast_argv_last - hast_argv[0]);
}

#else /* ! _SETPROCTITLE_USES_ENV */
void
setproctitle(const char *fmt __unused, ... __unused)
{
}
#endif /* _SETPROCTITLE_USES_ENV */
