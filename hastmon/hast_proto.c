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

#ifdef HAVE_HEADER_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <hast.h>
#include <ebuf.h>
#include <nv.h>
#include <pjdlog.h>
#include <proto.h>

#include "compat.h"
#include "hast_proto.h"

#ifndef ERPCMISMATCH
#define ERPCMISMATCH	EINVAL	
#endif

struct hast_main_header {
	/* Protocol version. */
	uint8_t		version;
	/* Size of nv headers. */
	uint32_t	size;
} __packed;

/*
 * Send the given nv structure via conn.
 * We keep headers in nv structure and pass data in separate argument.
 * There can be no data at all (data is NULL then).
 */
int
hast_proto_send(const struct hast_resource *res, struct proto_conn *conn,
    struct nv *nv, const void *data, size_t size)
{
	struct hast_main_header hdr;
	struct ebuf *eb;
	bool freedata;
	void *dptr, *hptr;
	size_t hsize;
	int ret;

	dptr = (void *)(uintptr_t)data;
	freedata = false;
	ret = -1;

	if (data != NULL) {
		nv_add_uint32(nv, size, "size");
		if (nv_error(nv) != 0) {
			errno = nv_error(nv);
			goto end;
		}
	}

	eb = nv_hton(nv);
	if (eb == NULL)
		goto end;

	hdr.version = HAST_PROTO_VERSION;
	hdr.size = htole32((uint32_t)ebuf_size(eb));
	if (ebuf_add_head(eb, &hdr, sizeof(hdr)) < 0)
		goto end;

	hptr = ebuf_data(eb, &hsize);
	if (proto_send(conn, hptr, hsize) < 0)
		goto end;
	if (data != NULL && proto_send(conn, dptr, size) < 0)
		goto end;

	ret = 0;
end:
	if (freedata)
		free(dptr);
	return (ret);
}

int
hast_proto_recv_hdr(const struct proto_conn *conn, struct nv **nvp)
{
	struct hast_main_header hdr;
	struct nv *nv;
	struct ebuf *eb;
	void *hptr;

	eb = NULL;
	nv = NULL;

	if (proto_recv(conn, &hdr, sizeof(hdr)) < 0)
		goto fail;

	if (hdr.version != HAST_PROTO_VERSION) {
		errno = ERPCMISMATCH;
		goto fail;
	}

	hdr.size = le32toh(hdr.size);

	eb = ebuf_alloc(hdr.size);
	if (eb == NULL)
		goto fail;
	if (ebuf_add_tail(eb, NULL, hdr.size) < 0)
		goto fail;
	hptr = ebuf_data(eb, NULL);
	assert(hptr != NULL);
	if (proto_recv(conn, hptr, hdr.size) < 0)
		goto fail;
	nv = nv_ntoh(eb);
	if (nv == NULL)
		goto fail;

	*nvp = nv;
	return (0);
fail:
	if (eb != NULL)
		ebuf_free(eb);
	return (-1);
}

int
hast_proto_recv_data(const struct hast_resource *res, struct proto_conn *conn,
    struct nv *nv, void *data, size_t size)
{
	unsigned int ii;
	bool freedata;
	size_t dsize;
	void *dptr;
	int ret;

	assert(data != NULL);
	assert(size > 0);

	ret = -1;
	freedata = false;
	dptr = data;

	dsize = nv_get_uint32(nv, "size");
	if (dsize == 0)
		(void)nv_set_error(nv, 0);
	else {
		if (proto_recv(conn, data, dsize) < 0)
			goto end;
	}

	ret = 0;
end:
if (ret < 0) printf("%s:%u %s\n", __func__, __LINE__, strerror(errno));
	if (freedata)
		free(dptr);
	return (ret);
}

int
hast_proto_recv(const struct hast_resource *res, struct proto_conn *conn,
    struct nv **nvp, void *data, size_t size)
{
	struct nv *nv;
	size_t dsize;
	int ret;

	ret = hast_proto_recv_hdr(conn, &nv);
	if (ret < 0)
		return (ret);
	dsize = nv_get_uint32(nv, "size");
	if (dsize == 0)
		(void)nv_set_error(nv, 0);
	else
		ret = hast_proto_recv_data(res, conn, nv, data, size);
	if (ret < 0)
		nv_free(nv);
	else
		*nvp = nv;
	return (ret);
}
