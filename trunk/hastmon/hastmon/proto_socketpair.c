/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
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
 */

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "compat.h"
#include "hast.h"
#include "pjdlog.h"
#include "proto_impl.h"

#define	SP_CTX_MAGIC	0x50c3741
struct sp_ctx {
	int			sp_magic;
	int			sp_fd[2];
	int			sp_side;
#define	SP_SIDE_UNDEF		0
#define	SP_SIDE_CLIENT		1
#define	SP_SIDE_SERVER		2
};

static void sp_close(void *ctx);

static int
sp_client(const char *addr, void **ctxp)
{
	struct sp_ctx *spctx;
	int ret;

	if (strcmp(addr, "socketpair://") != 0)
		return (-1);

	spctx = malloc(sizeof(*spctx));
	if (spctx == NULL)
		return (errno);

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, spctx->sp_fd) < 0) {
		ret = errno;
		free(spctx);
		return (ret);
	}

	spctx->sp_side = SP_SIDE_UNDEF;
	spctx->sp_magic = SP_CTX_MAGIC;
	*ctxp = spctx;

	return (0);
}

static int
sp_send(void *ctx, const unsigned char *data, size_t size)
{
	struct sp_ctx *spctx = ctx;
	int fd;

	PJDLOG_ASSERT(spctx != NULL);
	PJDLOG_ASSERT(spctx->sp_magic == SP_CTX_MAGIC);

	switch (spctx->sp_side) {
	case SP_SIDE_UNDEF:
		/*
		 * If the first operation done by the caller is proto_send(),
		 * we assume this the client.
		 */
		/* FALLTHROUGH */
		spctx->sp_side = SP_SIDE_CLIENT;
		/* Close other end. */
		close(spctx->sp_fd[1]);
	case SP_SIDE_CLIENT:
		PJDLOG_ASSERT(spctx->sp_fd[0] >= 0);
		fd = spctx->sp_fd[0];
		break;
	case SP_SIDE_SERVER:
		PJDLOG_ASSERT(spctx->sp_fd[1] >= 0);
		fd = spctx->sp_fd[1];
		break;
	default:
		abort();
	}

	/* Someone is just trying to decide about side. */
	if (data == NULL)
		return (0);

	return (proto_common_send(fd, data, size));
}

static int
sp_recv(void *ctx, unsigned char *data, size_t size)
{
	struct sp_ctx *spctx = ctx;
	int fd;

	PJDLOG_ASSERT(spctx != NULL);
	PJDLOG_ASSERT(spctx->sp_magic == SP_CTX_MAGIC);

	switch (spctx->sp_side) {
	case SP_SIDE_UNDEF:
		/*
		 * If the first operation done by the caller is proto_recv(),
		 * we assume this the server.
		 */
		/* FALLTHROUGH */
		spctx->sp_side = SP_SIDE_SERVER;
		/* Close other end. */
		close(spctx->sp_fd[0]);
	case SP_SIDE_SERVER:
		PJDLOG_ASSERT(spctx->sp_fd[1] >= 0);
		fd = spctx->sp_fd[1];
		break;
	case SP_SIDE_CLIENT:
		PJDLOG_ASSERT(spctx->sp_fd[0] >= 0);
		fd = spctx->sp_fd[0];
		break;
	default:
		abort();
	}

	/* Someone is just trying to decide about side. */
	if (data == NULL)
		return (0);

	return (proto_common_recv(fd, data, size));
}

static int
sp_descriptor_send(void *ctx, int fd)
{
	struct sp_ctx *spctx = ctx;

	PJDLOG_ASSERT(spctx != NULL);
	PJDLOG_ASSERT(spctx->sp_magic == SP_CTX_MAGIC);
	PJDLOG_ASSERT(spctx->sp_side == SP_SIDE_CLIENT);
	PJDLOG_ASSERT(spctx->sp_fd[0] >= 0);
	PJDLOG_ASSERT(fd > 0);

	return (proto_common_descriptor_send(spctx->sp_fd[0], fd));
}

static int
sp_descriptor_recv(void *ctx, int *fdp)
{
	struct sp_ctx *spctx = ctx;

	PJDLOG_ASSERT(spctx != NULL);
	PJDLOG_ASSERT(spctx->sp_magic == SP_CTX_MAGIC);
	PJDLOG_ASSERT(spctx->sp_side == SP_SIDE_SERVER);
	PJDLOG_ASSERT(spctx->sp_fd[1] >= 0);
	PJDLOG_ASSERT(fdp != NULL);

	return (proto_common_descriptor_recv(spctx->sp_fd[1], fdp));
}

static int
sp_descriptor(const void *ctx)
{
	const struct sp_ctx *spctx = ctx;

	PJDLOG_ASSERT(spctx != NULL);
	PJDLOG_ASSERT(spctx->sp_magic == SP_CTX_MAGIC);
	PJDLOG_ASSERT(spctx->sp_side == SP_SIDE_CLIENT ||
	    spctx->sp_side == SP_SIDE_SERVER);

	switch (spctx->sp_side) {
	case SP_SIDE_CLIENT:
		PJDLOG_ASSERT(spctx->sp_fd[0] >= 0);
		return (spctx->sp_fd[0]);
	case SP_SIDE_SERVER:
		PJDLOG_ASSERT(spctx->sp_fd[1] >= 0);
		return (spctx->sp_fd[1]);
	}

	abort();
}

static void
sp_close(void *ctx)
{
	struct sp_ctx *spctx = ctx;

	PJDLOG_ASSERT(spctx != NULL);
	PJDLOG_ASSERT(spctx->sp_magic == SP_CTX_MAGIC);

	switch (spctx->sp_side) {
	case SP_SIDE_UNDEF:
		close(spctx->sp_fd[0]);
		close(spctx->sp_fd[1]);
		break;
	case SP_SIDE_CLIENT:
		close(spctx->sp_fd[0]);
		break;
	case SP_SIDE_SERVER:
		close(spctx->sp_fd[1]);
		break;
	default:
		abort();
	}

	spctx->sp_magic = 0;
	free(spctx);
}

static struct hast_proto sp_proto = {
	.hp_name = "socketpair",
	.hp_client = sp_client,
	.hp_send = sp_send,
	.hp_recv = sp_recv,
	.hp_descriptor_send = sp_descriptor_send,
	.hp_descriptor_recv = sp_descriptor_recv,
	.hp_descriptor = sp_descriptor,
	.hp_close = sp_close
};

static __constructor void
sp_ctor(void)
{

	proto_register(&sp_proto, false);
}
