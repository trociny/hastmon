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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "hast.h"
#include "hast_proto.h"
#include "nv.h"
#include "pjdlog.h"
#include "proto.h"
#include "subr.h"

/* Path to configuration file. */
static const char *cfgpath = HAST_CONFIG;
/* Hastmon configuration. */
static struct hastmon_config *cfg;
/* Control connection. */
static struct proto_conn *controlconn;

enum {
	CMD_INVALID,
	CMD_CREATE,
	CMD_ROLE,
	CMD_STATUS,
};

static __dead2 void
usage(void)
{

	fprintf(stderr,
	    "       %s role [-d] [-c config] <init | primary | secondary | watchdog> all | name ...\n",
	    getprogname());
	fprintf(stderr,
	    "       %s status [-d] [-c config] [all | name ...]\n",
	    getprogname());
	fprintf(stderr,
	    "       %s dump [-d] [-c config] [all | name ...]\n",
	    getprogname());
	exit(EX_USAGE);
}

static int
control_set_role(struct nv *nv, const char *newrole)
{
	const char *res, *oldrole;
	unsigned int ii;
	int error, ret;

	ret = 0;

	for (ii = 0; ; ii++) {
		res = nv_get_string(nv, "resource%u", ii);
		if (res == NULL)
			break;
		pjdlog_prefix_set("[%s] ", res);
		error = nv_get_int16(nv, "error%u", ii);
		if (error != 0) {
			if (ret == 0)
				ret = error;
			pjdlog_warning("Received error %d from hastmon.", error);
			continue;
		}
		oldrole = nv_get_string(nv, "role%u", ii);
		if (strcmp(oldrole, newrole) == 0)
			pjdlog_debug(2, "Role unchanged (%s).", oldrole);
		else {
			pjdlog_debug(1, "Role changed from %s to %s.", oldrole,
			    newrole);
		}
	}
	pjdlog_prefix_set("%s", "");
	return (ret);
}

static int
control_status(struct nv *nv)
{
	unsigned int ii, jj;
	const char *str, *str1;
	int error, role, ret;

	ret = 0;

	for (ii = 0; ; ii++) {
		str = nv_get_string(nv, "resource%u", ii);
		if (str == NULL)
			break;
		printf("%s:\n", str);
		error = nv_get_int16(nv, "error%u", ii);
		if (error != 0) {
			if (ret == 0)
				ret = error;
			printf("  error: %d\n", error);
			continue;
		}
		role = nv_get_uint8(nv, "role%u", ii);
		printf("  role: %s\n", role2str(role));
		printf("  exec: %s\n",
		    nv_get_string(nv, "exec%u", ii));
		printf("  remoteaddr:");
		for(jj = 0; ;jj++) {
			str = nv_get_string(nv, "remoteaddr%u.%u", ii, jj);
			if (str == NULL)
				break;
			printf(" %s", str);
			switch (role) {
			case HAST_ROLE_PRIMARY:
			case HAST_ROLE_SECONDARY:			
				str = nv_get_string(nv, "remotestate%u.%u", ii, jj);
				if (str == NULL)
					break;
				printf("(%s)", str);
				break;
			case HAST_ROLE_WATCHDOG:			
				str = nv_get_string(nv, "remoterole%u.%u", ii, jj);
				if (str == NULL)
					break;
				str1 = nv_get_string(nv, "remotestate%u.%u", ii, jj);
				if (str == NULL)
					break;
				printf("(%s/%s)", str, str1);
				break;
			default:
				break;
			}
		}
		printf("\n");
		printf("  state: %s\n",
		       state2str(nv_get_uint8(nv, "state%u", ii)));
		printf("  attempts: %d from %d\n",
		       nv_get_int32(nv, "attempts%u", ii),
		       nv_get_int32(nv, "attempts_max%u", ii));
		printf("  complaints: %d for last %d sec (threshold %d)\n",
		       nv_get_int32(nv, "complaints%u", ii),
		       nv_get_int32(nv, "complaints_interval%u", ii),
		       nv_get_int32(nv, "complaints_critical%u", ii));
		printf("  heartbeat: %d sec\n",
		       nv_get_int32(nv, "heartbeat%u", ii));
	}
	return (ret);
}

int
main(int argc, char *argv[])
{
	struct nv *nv;
	int cmd, debug, error, ii;
	const char *optstr;

	debug = 0;

	if (argc == 1) {
		usage();
	} else if (strcmp(argv[1], "role") == 0) {
		cmd = CMD_ROLE;
		optstr = "c:dh";
	} else if (strcmp(argv[1], "status") == 0) {
		cmd = CMD_STATUS;
		optstr = "c:dh";
	} else
		usage();

	argc--;
	argv++;

	for (;;) {
		int ch;

		ch = getopt(argc, argv, optstr);
		if (ch == -1)
			break;
		switch (ch) {
		case 'c':
			cfgpath = optarg;
			break;
		case 'd':
			debug++;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (cmd == CMD_ROLE && argc == 0)
		usage();

	pjdlog_debug_set(debug);

	cfg = yy_config_parse(cfgpath, true);
	assert(cfg != NULL);

	switch (cmd) {
	case CMD_ROLE:
		/* Change role for the given resources. */
		if (argc < 2)
			usage();
		nv = nv_alloc();
		nv_add_uint8(nv, HASTCTL_CMD_SETROLE, "cmd");
		if (strcmp(argv[0], "init") == 0)
			nv_add_uint8(nv, HAST_ROLE_INIT, "role");
		else if (strcmp(argv[0], "primary") == 0)
			nv_add_uint8(nv, HAST_ROLE_PRIMARY, "role");
		else if (strcmp(argv[0], "secondary") == 0)
			nv_add_uint8(nv, HAST_ROLE_SECONDARY, "role");
		else if (strcmp(argv[0], "watchdog") == 0)
			nv_add_uint8(nv, HAST_ROLE_WATCHDOG, "role");
		else
			usage();
		for (ii = 0; ii < argc - 1; ii++)
			nv_add_string(nv, argv[ii + 1], "resource%d", ii);
		break;
	case CMD_STATUS:
		/* Obtain status of the given resources. */
		nv = nv_alloc();
		nv_add_uint8(nv, HASTCTL_CMD_STATUS, "cmd");
		if (argc == 0)
			nv_add_string(nv, "all", "resource%d", 0);
		else {
			for (ii = 0; ii < argc; ii++)
				nv_add_string(nv, argv[ii], "resource%d", ii);
		}
		break;
	default:
		assert(!"Impossible role!");
	}

	/* Setup control connection... */
	if (proto_client(cfg->hc_controladdr, &controlconn) < 0) {
		pjdlog_exit(EX_OSERR,
		    "Unable to setup control connection to %s",
		    cfg->hc_controladdr);
	}
	/* ...and connect to hastmon. */
	if (proto_connect(controlconn) < 0) {
		pjdlog_exit(EX_OSERR, "Unable to connect to hastmon via %s",
		    cfg->hc_controladdr);
	}
	/* Send the command to the server... */
	nv_add_uint8(nv, HASTREQ_TYPE_CONTROL, "type");
	if (hast_proto_send(NULL, controlconn, nv, NULL, 0) < 0) {
		pjdlog_exit(EX_UNAVAILABLE,
		    "Unable to send command to hastmon via %s",
		    cfg->hc_controladdr);
	}
	nv_free(nv);
	/* ...and receive reply. */
	if (hast_proto_recv(NULL, controlconn, &nv, NULL, 0) < 0) {
		pjdlog_exit(EX_UNAVAILABLE,
		    "cannot receive reply from hastmon via %s",
		    cfg->hc_controladdr);
	}

	error = nv_get_int16(nv, "error");
	if (error != 0) {
		pjdlog_exitx(EX_SOFTWARE, "Error %d received from hastmon.",
		    error);
	}
	nv_set_error(nv, 0);

	switch (cmd) {
	case CMD_ROLE:
		error = control_set_role(nv, argv[0]);
		break;
	case CMD_STATUS:
		error = control_status(nv);
		break;
	default:
		assert(!"Impossible role!");
	}

	exit(error);
}
