/*-
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

#include <string.h>
#include <time.h>

#ifdef HAVE_CRYPTO
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#endif

#include "auth.h"
#include "hast.h"
#include "nv.h"
#include "pjdlog.h"
#include "proto.h"

#ifdef HAVE_CRYPTO

#define MAXDIFTIME	10

typedef int (DIGEST_Init)(void *);
typedef int (DIGEST_Update)(void *, const unsigned char *, size_t);
typedef int (DIGEST_Final)(char *, void *);

typedef struct Algorithm_t {
	const char *name;
	size_t digest_length;
	DIGEST_Init *Init;
	DIGEST_Update *Update;
	DIGEST_Final *Final;
} Algorithm_t;

typedef union {
	MD5_CTX md5;
	SHA_CTX sha1;
	SHA256_CTX sha256;
	RIPEMD160_CTX ripemd160;
} DIGEST_CTX;

#define MAX_DIGEST_LENGTH 65

/* Algorithm function table */

struct Algorithm_t algorithm[] = {
	{ "UNDEF",
	  0,
	  NULL,
	  NULL,
	  NULL },
	{ "MD5",
	  MD5_DIGEST_LENGTH,
	  (DIGEST_Init*) &MD5_Init,
	  (DIGEST_Update*) &MD5_Update,
	  (DIGEST_Final*) &MD5_Final},
	{ "SHA1",
	  SHA_DIGEST_LENGTH,
	  (DIGEST_Init*) &SHA1_Init,
	  (DIGEST_Update*) &SHA1_Update,
	  (DIGEST_Final*) &SHA1_Final },
	{ "SHA256",
	  SHA256_DIGEST_LENGTH,
	  (DIGEST_Init*) &SHA256_Init,
	  (DIGEST_Update*) &SHA256_Update,
	  (DIGEST_Final*) &SHA256_Final },
	{ "RIPEMD160",
	  RIPEMD160_DIGEST_LENGTH,
	  (DIGEST_Init*) &RIPEMD160_Init,
	  (DIGEST_Update*) &RIPEMD160_Update,
	  (DIGEST_Final*) &RIPEMD160_Final }
};

static void
make_secret(char *buf, size_t size, char *secret, time_t now,
    struct proto_conn *conn, bool reverse)
{
	char addr1[256], addr2[256];
	int len;

	proto_local_address(conn, reverse ? addr1 : addr2, sizeof(addr1));
	proto_remote_address(conn, reverse ? addr2 : addr1, sizeof(addr1));

	len = snprintf(buf, size, "%zu%s%s%s", now, addr1, addr2, secret);
	pjdlog_debug(2, "secret: %s", buf);

	PJDLOG_ASSERT(len < size);
}

void
auth_add(struct nv *nv, struct proto_conn *conn, struct hast_auth *key)
{
	char secret[HAST_KEYMAX + 512 + 128];
	char hash[MAX_DIGEST_LENGTH];
	time_t now;
	DIGEST_CTX ctx;
	Algorithm_t *alg;

	PJDLOG_ASSERT(key != NULL);
	PJDLOG_ASSERT(key->au_algo >= HAST_AUTH_UNDEF && key->au_algo < HAST_AUTH_MAX);

	if (key->au_algo == HAST_AUTH_UNDEF) {
		pjdlog_debug(2, "Authentication is not used.");
		return;
	}

	now = time(NULL);
	nv_add_uint64(nv, now, "now");
	make_secret(secret, sizeof(secret), key->au_secret, now, conn, true);

	alg = &algorithm[key->au_algo];

	alg->Init(&ctx);
	alg->Update(&ctx, (unsigned char *)secret, strlen(secret));
	alg->Final(hash, &ctx);

	nv_add_uint8_array(nv, (uint8_t *)hash, alg->digest_length,
	    "auth_hash");
}

bool
auth_confirm(struct nv *nv, struct proto_conn *conn, struct hast_auth *key)
{
	char secret[HAST_KEYMAX + 512 + 128];
	char chash[MAX_DIGEST_LENGTH];
	const unsigned char *rhash;
	DIGEST_CTX ctx;
	Algorithm_t *alg;
	time_t now, then;
	size_t size;

	PJDLOG_ASSERT(key != NULL);
	PJDLOG_ASSERT(key->au_algo >= HAST_AUTH_UNDEF && key->au_algo < HAST_AUTH_MAX);

	if (key->au_algo == HAST_AUTH_UNDEF) {
		pjdlog_debug(2, "Authentication is not used.");
		return true;
	}

	alg = &algorithm[key->au_algo];
	rhash = nv_get_uint8_array(nv, &size, "auth_hash");
	if (rhash == NULL) {
		pjdlog_error("Hash is missing.");
		return false;
	}
	if (size != alg->digest_length) {
		pjdlog_error("Invalid hash size (%zu) for %s, should be %zu.",
		    size, alg->name, alg->digest_length);
		return false;
	}

	then = nv_get_uint64(nv, "now");
	now = time(NULL);
	if (then - now >= MAXDIFTIME || now - then >= MAXDIFTIME) {
		pjdlog_error("Time difference (%zu - %zu) is more than tolerable (%d).",
		    then, now, MAXDIFTIME);
		return false;
	}

	make_secret(secret, sizeof(secret), key->au_secret, then, conn, false);

	alg->Init(&ctx);
	alg->Update(&ctx, (unsigned char *)secret, strlen(secret));
	alg->Final(chash, &ctx);

	if (bcmp(rhash, chash, alg->digest_length) != 0) {
		pjdlog_error("Hash mismatch.");
		return false;
	}

	return true;
}

int
str2algo (const char *str)
{
	int ii;

	PJDLOG_ASSERT(str != NULL);

	for (ii = 1; ii < HAST_AUTH_MAX; ii++)
		if (strcmp(str, algorithm[ii].name) == 0)
			return ii;

	return HAST_AUTH_UNDEF;
}

#else /* !HAVE_CRYPTO */

void
auth_add(struct nv *nv, struct proto_conn *conn, struct hast_auth *key)
{

	PJDLOG_ASSERT(key != NULL);
	PJDLOG_ASSERT(key->au_algo >= HAST_AUTH_UNDEF && key->au_algo < HAST_AUTH_MAX);

	return;
}

bool
auth_confirm(struct nv *nv, struct proto_conn *conn, struct hast_auth *key)
{

	PJDLOG_ASSERT(key != NULL);
	PJDLOG_ASSERT(key->au_algo >= HAST_AUTH_UNDEF && key->au_algo < HAST_AUTH_MAX);

	return true;
}

int
str2algo (const char *str __unused)
{
	return HAST_AUTH_UNDEF;
}

#endif /* HAVE_CRYPTO */
