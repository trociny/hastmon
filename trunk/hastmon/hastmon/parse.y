%{
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
 *
 * $FreeBSD$
 */

#include <sys/param.h>	/* MAXHOSTNAMELEN */
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <pjdlog.h>

#include "auth.h"
#include "hast.h"

extern int depth;
extern int lineno;

extern FILE *yyin;
extern char *yytext;

static struct hastmon_config *lconfig;
static struct hast_resource *curres;
static bool mynode;

static char depth0_control[HAST_ADDRSIZE];
static char depth0_listen[HAST_ADDRSIZE];
static char depth0_exec[PATH_MAX];
static int depth0_timeout;
static int depth0_attempts;
static int depth0_heartbeat_interval;
static int depth0_complaint_count;
static int depth0_complaint_interval;
static struct hast_auth depth0_key;

extern void yyrestart(FILE *);

static int
isitme(const char *name)
{
	char buf[MAXHOSTNAMELEN];
	char *pos;
#ifdef _KERN_HOSTUUID
	size_t bufsize;
#endif

	/*
	 * First check if the give name matches our full hostname.
	 */
	if (gethostname(buf, sizeof(buf)) < 0) {
		pjdlog_errno(LOG_ERR, "gethostname() failed");
		return (-1);
	}
 	if (strcmp(buf, name) == 0)
		return (1);

	/*
	 * Now check if it matches first part of the host name.
	 */
	pos = strchr(buf, '.');
	if (pos != NULL && pos != buf && strncmp(buf, name, pos - buf) == 0)
		return (1);

#ifdef _KERN_HOSTUUID
	/*
	 * At the end check if name is equal to our host's UUID.
	 */
	bufsize = sizeof(buf);
	if ((sysctlbyname("kern.hostuuid", buf, &bufsize, NULL, 0) == 0) &&
	    (strcasecmp(buf, name) == 0))
		return (1);
#endif

	/*
	 * Looks like this isn't about us.
	 */
	return (0);
}

void
yyerror(const char *str)
{

 	pjdlog_error("Unable to parse configuration file at line %d near '%s': %s",
	    lineno, yytext, str);
}

struct hastmon_config *
yy_config_parse(const char *config, bool exitonerror)
{
	int ret;

	curres = NULL;
	mynode = false;
	depth = 0;
	lineno = 0;

	depth0_timeout = HAST_TIMEOUT;
	depth0_heartbeat_interval = HAST_HBEAT_INT;	
	depth0_complaint_count = HAST_CMPLNT_CNT;
	depth0_complaint_interval = HAST_CMPLNT_INT;	
	strlcpy(depth0_control, HAST_CONTROL, sizeof(depth0_control));
	strlcpy(depth0_listen, HAST_LISTEN, sizeof(depth0_listen));
	depth0_exec[0] = '\0';
	depth0_key.au_algo = HAST_AUTH_UNDEF;
	depth0_key.au_secret[0] = '\0';

	lconfig = calloc(1, sizeof(*lconfig));
	if (lconfig == NULL) {
		pjdlog_error("Unable to allocate memory for configuration.");
		if (exitonerror)
			exit(EX_TEMPFAIL);
		return (NULL);
	}
	TAILQ_INIT(&lconfig->hc_friends);
	TAILQ_INIT(&lconfig->hc_resources);

	yyin = fopen(config, "r");
	if (yyin == NULL) {
		pjdlog_errno(LOG_ERR, "Unable to open configuration file %s",
		    config);
		yy_config_free(lconfig);
		if (exitonerror)
			exit(EX_OSFILE);
		return (NULL);
	}
	yyrestart(yyin);

	ret = yyparse();
	fclose(yyin);
	if (ret != 0) {
		yy_config_free(lconfig);
		if (exitonerror)
			exit(EX_CONFIG);
		return (NULL);
	}

	/*
	 * Let's see if everything is set up.
	 */
	if (lconfig->hc_controladdr[0] == '\0') {
		strlcpy(lconfig->hc_controladdr, depth0_control,
		    sizeof(lconfig->hc_controladdr));
	}
	if (lconfig->hc_listenaddr[0] == '\0') {
		strlcpy(lconfig->hc_listenaddr, depth0_listen,
		    sizeof(lconfig->hc_listenaddr));
	}
	TAILQ_FOREACH(curres, &lconfig->hc_resources, hr_next) {
		assert(TAILQ_FIRST(&curres->hr_remote) != NULL);

		if (curres->hr_timeout == -1) {
			/*
			 * Timeout is not set at resource-level.
			 * Use global or default setting.
			 */
			curres->hr_timeout = depth0_timeout;
		}
		if (curres->hr_heartbeat_interval == -1) {
			/*
			 * Heartbeat interval is not set at resource-level.
			 * Use global or default setting.
			 */
			curres->hr_heartbeat_interval = depth0_heartbeat_interval;
		}
		if (curres->hr_key.au_algo == HAST_AUTH_UNDEF) {
			/*
			 * Key is not set at resource-level.
			 * Use global setting.
			 */
			curres->hr_key = depth0_key;
		}
		if (curres->hr_complaint_critical_cnt == -1) {
			/*
			 * Complaint count is not set at resource-level.
			 * Use global or default setting.
			 */
			curres->hr_complaint_critical_cnt = depth0_complaint_count;
		}
		if (curres->hr_complaint_interval == -1) {
			/*
			 * Complaint interval is not set at resource-level.
			 * Use global or default setting.
			 */
			curres->hr_complaint_interval = depth0_complaint_interval;
		}
		if (curres->hr_exec[0] == '\0') {
			/*
			 * Exec is not set at resource-level.
			 * Use global or default setting.
			 */
			strlcpy(curres->hr_exec, depth0_exec,
			    sizeof(curres->hr_exec));
		}
	}

	return (lconfig);
}

void
yy_resource_free(struct hast_resource *res)
{
	struct hast_address *addr;
	struct hast_remote *remote;

	while ((addr = TAILQ_FIRST(&res->hr_friends)) != NULL) {
		TAILQ_REMOVE(&res->hr_friends, addr, a_next);
		free(addr);
	}
	while ((remote = TAILQ_FIRST(&res->hr_remote)) != NULL) {
		TAILQ_REMOVE(&res->hr_remote, remote, r_next);
		free(remote);
	}
	free(res);
}

void
yy_config_free(struct hastmon_config *config)
{
	struct hast_resource *res;
	struct hast_address *addr;

	while ((addr = TAILQ_FIRST(&config->hc_friends)) != NULL) {
		TAILQ_REMOVE(&config->hc_friends, addr, a_next);
		free(addr);
	}
	while ((res = TAILQ_FIRST(&config->hc_resources)) != NULL) {
		TAILQ_REMOVE(&config->hc_resources, res, hr_next);
		yy_resource_free(res);
	}
	free(config);
}
%}

%token ALGORITHM ATTEMPTS CB COMPLAINT_COUNT COMPLAINT_INTERVAL CONTROL EXEC
%token FRIENDS HEARTBEAT_INTERVAL KEY LISTEN NUM ON OB PORT PRIORITY 
%token REMOTE RESOURCE SECRET STR TIMEOUT

%union
{
	int num;
	char *str;
}

%token <num> NUM
%token <str> STR

%%

statements:
	|
	statements statement
	;

statement:
	control_statement
	|
	listen_statement
	|
	timeout_statement
	|
	attempts_statement
	|
	friends_statement
	|
	heartbeat_interval_statement
	|
	key_statement
	|
	complaint_count_statement
	|
	complaint_interval_statement
	|
	exec_statement
	|
	node_statement
	|
	resource_statement
	;

control_statement:	CONTROL STR
	{
		switch (depth) {
		case 0:
			if (strlcpy(depth0_control, $2,
			    sizeof(depth0_control)) >=
			    sizeof(depth0_control)) {
				pjdlog_error("control argument is too long.");
				free($2);
				return (1);
			}
			break;
		case 1:
			if (!mynode)
				break;
			if (strlcpy(lconfig->hc_controladdr, $2,
			    sizeof(lconfig->hc_controladdr)) >=
			    sizeof(lconfig->hc_controladdr)) {
				pjdlog_error("control argument is too long.");
				free($2);
				return (1);
 			}
 			break;
		default:
			assert(!"control at wrong depth level");
		}
		free($2);
	}
	;

listen_statement:	LISTEN STR
	{
		switch (depth) {
		case 0:
			if (strlcpy(depth0_listen, $2,
			    sizeof(depth0_listen)) >=
			    sizeof(depth0_listen)) {
				pjdlog_error("listen argument is too long.");
				free($2);
				return (1);
			}
			break;
		case 1:
			if (!mynode)
				break;
			if (strlcpy(lconfig->hc_listenaddr, $2,
			    sizeof(lconfig->hc_listenaddr)) >=
			    sizeof(lconfig->hc_listenaddr)) {
				pjdlog_error("listen argument is too long.");
				free($2);
				return (1);
			}
			break;
		default:
			assert(!"listen at wrong depth level");
		}
		free($2);
	}
	;

timeout_statement:	TIMEOUT NUM
	{
		switch (depth) {
		case 0:
			depth0_timeout = $2;
			break;
		case 1:
			if (curres != NULL)
				curres->hr_timeout = $2;
			break;
		default:
			assert(!"timeout at wrong depth level");
		}
	}
	;

attempts_statement:	ATTEMPTS NUM
	{
		switch (depth) {
		case 0:
			depth0_attempts = $2;
			break;
		case 1:
		case 2:
			if (curres != NULL)
				curres->hr_local_attempts_max = $2;
			break;
		default:
			assert(!"attempts at wrong depth level");
		}
	}
	;

heartbeat_interval_statement:	HEARTBEAT_INTERVAL NUM
	{
		switch (depth) {
		case 0:
			depth0_heartbeat_interval = $2;
			break;
		case 1:
		case 2:
			if (curres != NULL)
				curres->hr_heartbeat_interval = $2;
			break;
		default:
			assert(!"heartbeat_interval at wrong depth level");
		}
	}
	;

complaint_count_statement:	COMPLAINT_COUNT NUM
	{
		switch (depth) {
		case 0:
			depth0_complaint_count = $2;
			break;
		case 1:
		case 2:
			if (curres != NULL)
				curres->hr_complaint_critical_cnt = $2;
			break;
		default:
			assert(!"complaint_count at wrong depth level");
		}
	}
	;

complaint_interval_statement:	COMPLAINT_INTERVAL NUM
	{
		switch (depth) {
		case 0:
			depth0_complaint_interval = $2;
			break;
		case 1:
		case 2:
			if (curres != NULL)
				curres->hr_complaint_interval = $2;
			break;
		default:
			assert(!"complaint_interval at wrong depth level");
		}
	}
	;

exec_statement:		EXEC STR
	{
		switch (depth) {
		case 0:
			if (strlcpy(depth0_exec, $2, sizeof(depth0_exec)) >=
			    sizeof(depth0_exec)) {
				pjdlog_error("Exec path is too long.");
				free($2);
				return (1);
			}
			break;
		case 1:
			if (curres == NULL)
				break;
			if (strlcpy(curres->hr_exec, $2,
			    sizeof(curres->hr_exec)) >=
			    sizeof(curres->hr_exec)) {
				pjdlog_error("Exec path is too long.");
				free($2);
				return (1);
			}
			break;
		default:
			assert(!"exec at wrong depth level");
		}
		free($2);
	}
	;

node_statement:		ON node_start OB node_entries CB
	{
		mynode = false;
	}
	;

node_start:	STR
	{
		switch (isitme($1)) {
		case -1:
			free($1);
			return (1);
		case 0:
			break;
		case 1:
			mynode = true;
			break;
		default:
			assert(!"invalid isitme() return value");
		}
		free($1);
	}
	;

node_entries:
	|
	node_entries node_entry
	;

node_entry:
	control_statement
	|
	listen_statement
	|
	attempts_statement
	|
	friends_statement
	|
	priority_statement
	|
	heartbeat_interval_statement
	|
	complaint_count_statement
	|
	complaint_interval_statement
	;

key_statement:		KEY OB key_entries CB
	;

key_entries:
	|
	key_entries key_entry
	;

key_entry:
	algorithm_statement
	|
	secret_statement
	;

algorithm_statement:		ALGORITHM STR
	{
		switch (depth) {
		case 1:
			if ((depth0_key.au_algo = str2algo($2)) == HAST_AUTH_UNDEF) {
				pjdlog_error("Unknown algorithm: %s.", $2);
				free($2);
				return (1);
			}
			break;
		case 2:
			if (curres == NULL)
				break;
			if ((curres->hr_key.au_algo = str2algo($2)) == HAST_AUTH_UNDEF) {
				pjdlog_error("Unknown algorithm: %s.", $2);
				free($2);
				return (1);
			}
			break;
		default:
			assert(!"key at wrong depth level");
		}
		free($2);
	}
	;

secret_statement:		SECRET STR
	{
		switch (depth) {
		case 1:
			if (strlcpy(depth0_key.au_secret, $2,
				sizeof(depth0_key.au_secret)) >=
			    sizeof(depth0_key.au_secret)) {
				pjdlog_error("Secret is too long.");
				free($2);
				return (1);
			}
			break;
		case 2:
			if (curres == NULL)
				break;
			if (strlcpy(curres->hr_key.au_secret, $2,
				sizeof(depth0_key.au_secret)) >=
			    sizeof(depth0_key.au_secret)) {
				pjdlog_error("Secret is too long.");
				free($2);
				return (1);
			}
			break;
		default:
			assert(!"key at wrong depth level");
		}
		free($2);
	}
	;

resource_statement:	RESOURCE resource_start OB resource_entries CB
	{
		if (curres != NULL) {
			/*
			 * Let's see there are some resource-level settings
			 * that we can use for node-level settings.
			 */

			/*
			 * Remote address has to be configured at this point.
			 */
			if (TAILQ_FIRST(&curres->hr_remote) == NULL) {
				pjdlog_error("Remote address not configured for resource %s.",
				    curres->hr_name);
				return (1);
			}
			
			/*
			 *  Exec has to be configured at this point.
			 */
			if (curres->hr_exec[0] == '\0') {
				pjdlog_error("Exec not configured for resource %s.",
				    curres->hr_name);
				return (1);
			}
			
			/* Put it onto resource list. */
			TAILQ_INSERT_TAIL(&lconfig->hc_resources, curres, hr_next);
			curres = NULL;
		}
	}
	;

resource_start:	STR
	{
		/*
		 * Clear those, so we can tell if they were set at
		 * resource-level or not.
		 */

		curres = calloc(1, sizeof(*curres));
		if (curres == NULL) {
			pjdlog_error("Unable to allocate memory for resource.");
			free($1);
			return (1);
		}
		if (strlcpy(curres->hr_name, $1,
		    sizeof(curres->hr_name)) >=
		    sizeof(curres->hr_name)) {
			pjdlog_error("Resource name is too long.");
			free($1);
			return (1);
		}
		free($1);
		curres->hr_role = HAST_ROLE_INIT;
		curres->hr_previous_role = HAST_ROLE_INIT;
		curres->hr_timeout = -1;
		curres->hr_priority = 100;
		curres->hr_heartbeat_interval = -1;
		curres->hr_exec[0] = '\0';
		curres->hr_local_attempts_max = HAST_ATTEMPTS;
		TAILQ_INIT(&curres->hr_friends);
		curres->hr_remote_cnt = 0;
		TAILQ_INIT(&curres->hr_remote);
		curres->hr_key.au_algo = HAST_AUTH_UNDEF;
		curres->hr_key.au_secret[0] = '\0';
		curres->hr_complaint_critical_cnt = -1;
		curres->hr_complaint_interval = -1;
		TAILQ_INIT(&curres->hr_complaints);
	}
	;

resource_entries:
	|
	resource_entries resource_entry
	;

resource_entry:
	timeout_statement
	|
	attempts_statement
	|
	friends_statement
	|
	heartbeat_interval_statement
	|
	key_statement
	|
	complaint_count_statement
	|
	complaint_interval_statement
	|
	exec_statement
	|
	resource_node_statement
	;

resource_node_statement:ON resource_node_start OB resource_node_entries CB
	{
		mynode = false;
	}
	;

resource_node_start:	STR
	{
		if (curres != NULL) {
			switch (isitme($1)) {
			case -1:
				free($1);
				return (1);
			case 0:
				break;
			case 1:
				mynode = true;
				break;
			default:
				assert(!"invalid isitme() return value");
			}
			free($1);
		}
	}
	;

resource_node_entries:
	|
	resource_node_entries resource_node_entry
	;

resource_node_entry:
	attempts_statement
	|
	friends_statement
	|
	remote_statement
	|
	priority_statement
	|
	heartbeat_interval_statement
	|
	complaint_count_statement
	|
	complaint_interval_statement
	;

remote_statement:	REMOTE remote_addresses
	;

remote_addresses:
	|
	remote_addresses remote_address
	;

remote_address:		STR
	{
		struct hast_remote *remote;

		assert(depth == 2);
		if (mynode) {
			assert(curres != NULL);
			remote = calloc(1, sizeof(*remote));
			if (remote == NULL) {
				errx(EX_TEMPFAIL,
				     "cannot allocate memory for resource");
			}
			if (strlcpy(remote->r_addr, $1,
				    sizeof(remote->r_addr)) >=
			    sizeof(remote->r_addr)) {
				pjdlog_error("remote argument too long");
				free($1);
				return (1);
			}
			free($1);
			remote->r_res = curres;
			remote->r_ncomp = curres->hr_remote_cnt;
			TAILQ_INSERT_TAIL(&curres->hr_remote, remote, r_next);
			curres->hr_remote_cnt++;
		}
	}
	;

friends_statement:	FRIENDS friend_addresses
	;

friend_addresses:
	|
	friend_addresses friend_address
	;

friend_address:		STR
	{
		struct hast_address *addr;

		switch (depth) {
		case 0:
		case 1:
			addr = calloc(1, sizeof(*addr));
			if (addr == NULL) {
				errx(EX_TEMPFAIL,
				     "cannot allocate memory for resource");
			}
			if (strlcpy(addr->a_addr, $1,
				    sizeof(addr->a_addr)) >=
			    sizeof(addr->a_addr)) {
				pjdlog_error("address argument too long");
				free($1);
				return (1);
			}
			free($1);
			TAILQ_INSERT_TAIL(&lconfig->hc_friends, addr, a_next);
			break;
		case 2:
			if (mynode) {
				assert(curres != NULL);
				addr = calloc(1, sizeof(*addr));
				if (addr == NULL) {
					errx(EX_TEMPFAIL,
					     "cannot allocate memory for resource");
				}
				if (strlcpy(addr->a_addr, $1,
					    sizeof(addr->a_addr)) >=
				    sizeof(addr->a_addr)) {
					pjdlog_error("address argument too long");
					free($1);
					return (1);
				}
				free($1);
				TAILQ_INSERT_TAIL(&curres->hr_friends, addr, a_next);
			}
			break;
		default:
			assert(!"friends at wrong depth level");			
		}
	}
	;

priority_statement:	PRIORITY NUM
	{
		assert(depth == 2);
		if (mynode) {
			curres->hr_priority = $2;
			if (curres->hr_priority < 0) {
				pjdlog_error("priority should be greater or equal zero");
				return (1);
			}
		}
	}
	;
