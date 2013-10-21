/*-
 * Copyright (c) 2009-2010 The FreeBSD Foundation
 * Copyright (c) 2010 Mikolaj Golub <to.my.trociny@gmail.com>
 * All rights reserved.
 *
 * This software wss developed by Mikolaj Golub. The source is derived
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
 */

#ifndef	_HAST_H_
#define	_HAST_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#ifdef HAVE_DEFINE_TAILQ_FOREACH_SAFE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "auth.h"
#include "proto.h"

#define	HAST_PROTO_VERSION	0

#define	EHAST_OK		0
#define	EHAST_NOENTRY		1
#define	EHAST_INVALID		2
#define	EHAST_NOMEMORY		3
#define	EHAST_UNIMPLEMENTED	4
#define	EHAST_AUTHFAILED	5

#define HASTREQ_TYPE_UNKNOWN	0
#define HASTREQ_TYPE_CONTROL	1
#define HASTREQ_TYPE_COMPLAINT	2

#define	HASTCTL_CMD_UNKNOWN	0
#define	HASTCTL_CMD_SETROLE	1
#define	HASTCTL_CMD_STATUS	2

#define	HAST_ROLE_UNDEF		0
#define	HAST_ROLE_INIT		1
#define	HAST_ROLE_PRIMARY	2
#define	HAST_ROLE_SECONDARY	3
#define	HAST_ROLE_WATCHDOG	4

#define	HAST_STATE_UNKNOWN	0
#define	HAST_STATE_READYTORUN	1
#define	HAST_STATE_STARTING	2
#define	HAST_STATE_RUN		3
#define	HAST_STATE_STOPPING	4
#define	HAST_STATE_STOPPED	5
#define	HAST_STATE_FAILED	6

#define HIO_UNDEF		0
#define HIO_STATE		1

#define	HAST_TIMEOUT	5
#define	HAST_CONFIG	"/usr/local/etc/hastmon.conf"
#define	HAST_CONTROL	"/var/run/hastmonctl"
#define	HAST_PORT	8458
#define	HAST_LISTEN	"tcp4://0.0.0.0:8458"
#define	HAST_PIDFILE	"/var/run/hastmon.pid"
#define HAST_ATTEMPTS	5
#define HAST_HBEAT_INT	10
#define HAST_CMPLNT_CNT	3
#define HAST_CMPLNT_INT	60

#define	HAST_ADDRSIZE	1024
#define	HAST_TOKEN_SIZE	16
#define HAST_KEYMAX	1024

struct hastmon_config {
	/* Address to communicate with hastctl(8). */
	char	 hc_controladdr[HAST_ADDRSIZE];
	/* Protocol-specific data. */
	struct proto_conn *hc_controlconn;
	/* Incoming control connection. */
	struct proto_conn *hc_controlin;
	/* Address to listen on. */
	char	 hc_listenaddr[HAST_ADDRSIZE];
	/* Protocol-specific data. */
	struct proto_conn *hc_listenconn;
	/* Global list of addresses that can connect to us. */
	TAILQ_HEAD(, hast_address) hc_friends;
	/* List of resources. */
	TAILQ_HEAD(, hast_resource) hc_resources;
};

/*
 * Structure that describes single resource.
 */
struct hast_resource {
	/* Resource name. */
	char	hr_name[NAME_MAX];

	/* Path to a program to execute on various events. */
	char	hr_exec[PATH_MAX];

	/* Resource unique identifier. */
	uint64_t hr_resuid;

	/* This node priority being primary for the resourse. */
	int hr_priority;

	/* Resource role: HAST_ROLE_{INIT,PRIMARY,SECONDARY,WATCHDOG}. */
	int	hr_role;
	/* Previous resource role: HAST_ROLE_{INIT,PRIMARY,SECONDARY,WATCHDOG}. */
	int	hr_previous_role;
	/* Resource role on start: HAST_ROLE_{INIT,PRIMARY,SECONDARY,WATCHDOG}. */
	int	hr_role_on_start;
	/* PID of child worker process. 0 - no child. */
	pid_t	hr_workerpid;
	/* Control connection between parent and child. */
	struct proto_conn *hr_ctrl;
	/* Events from child to parent. */
	struct proto_conn *hr_event;
	/* Connection timeout. */
	int	hr_timeout;
	/* Resource state: HAST_STATE_{UNKNOWN,STARTING,RUN,STOPPING,STOPPED,FAILED}. */
	int	hr_local_state;
	/* Number of attemps to start resource. */
	int	hr_local_attempts;
	/* Number of attemps after which the resourse is considered failed. */
	int	hr_local_attempts_max;

	/* Time of the last received STATUS request from a remote (watchdog). */
	time_t	hr_remote_lastcheck;

	/* Per resource list of addresses that can connect to us. */
	TAILQ_HEAD(, hast_address) hr_friends;

	/* Key used for authentication. */
	struct hast_auth hr_key;

	/* Number of remote components. */
	int hr_remote_cnt;

	/* List of remote components. */
	TAILQ_HEAD(, hast_remote) hr_remote;

	/* Number of complaints we want to receive before failovering. */
	int	hr_complaint_critical_cnt;
	/* Period of time (in sec) complaints are counted. */
	int	hr_complaint_interval;

	/* Period of time (in sec) between heartbeats. */
	int	hr_heartbeat_interval;

	/* Complaints. */
	TAILQ_HEAD(, hast_complaint) hr_complaints;

	/* Locked used to synchronize access to resourse. */
	pthread_mutex_t hr_lock;

	/* Next resource. */
	TAILQ_ENTRY(hast_resource) hr_next;
};

struct hast_remote {
	/* Address of the remote component. */
	char	r_addr[HAST_ADDRSIZE];
	/* Connection for incoming data. */
	struct proto_conn *r_in;
	/* Connection for outgoing data. */
	struct proto_conn *r_out;
	/* Token to verify both in and out connection are coming from
	   the same node (not necessarily from the same address). */
	unsigned char r_token[HAST_TOKEN_SIZE];
	/* Remote role: HAST_ROLE_{INIT,PRIMARY,SECONDARY,WATCHDOG}. */
	int	r_role;
	/* Remote state: HAST_STATE_{UNKNOWN,STARTING,RUN,STOPPING,STOPPED}. */
	int	r_state;
	/* Pointer to resurce */
	struct hast_resource	*r_res;
	/* This component number */
	int r_ncomp;
	/* Next remote. */
	TAILQ_ENTRY(hast_remote) r_next;
};

struct hast_address {
	char	a_addr[HAST_ADDRSIZE];
	TAILQ_ENTRY(hast_address) a_next;
};

struct hast_complaint {
	time_t	c_time;
	TAILQ_ENTRY(hast_complaint) c_next;
};

struct hastmon_config *yy_config_parse(const char *config, bool exitonerror);
void yy_resource_free(struct hast_resource *res);
void yy_config_free(struct hastmon_config *config);

void yyerror(const char *);
int yylex(void);
int yyparse(void);

#endif	/* !_HAST_H_ */
