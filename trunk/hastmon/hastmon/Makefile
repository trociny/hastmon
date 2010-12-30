PREFIX?=	/usr/local

MKC_COMMON_DEFINES.Linux+=	-D_NO_SO_LEN
MKC_COMMON_DEFINES.FreeBSD+=	-D_KERN_HOSTUUID

MKC_CHECK_HEADERS+=	pthread_np.h
MKC_CHECK_FUNCS1+=	pthread_mutex_isowned_np:pthread_np.h

MKC_CHECK_FUNCS0+=	arc4random:stdlib.h
MKC_CHECK_FUNCS2+=	arc4random_buf:stdlib.h

MKC_CHECK_FUNCS2+=	pthread_condattr_setclock:pthread.h

MKC_CHECK_HEADERS+=	machine/vmparam.h sys/user.h
MKC_CHECK_HEADERS+=	sys/endian.h

MKC_CHECK_DEFINES+=	TAILQ_FOREACH_SAFE:sys/queue.h

MKC_CHECK_FUNCS3+=	strlcat:string.h strlcpy:string.h
MKC_SOURCE_FUNCLIBS+=	strlcat strlcpy

MKC_CHECK_FUNCS1+=	setproctitle:unistd.h setproctitle:setproctitle.h

MKC_CHECK_FUNCS1+=	closefrom:unistd.h

MKC_CHECK_FUNCS1+=	htole64:sys/types.h

PROG=	hastmon
SRCS+=	control.c
SRCS+=	ebuf.c event.c
SRCS+=	hast_proto.c hastmon.c hooks.c
SRCS+=	nv.c
SRCS+=	secondary.c
SRCS+=	parse.y pjdlog.c primary.c
SRCS+=	proto.c proto_common.c proto_socketpair.c proto_tcp4.c proto_uds.c
SRCS+=	subr.c
SRCS+=	token.l
SRCS+=	y.tab.h
SRCS+=	watchdog.c
SRCS+=	auth.c
SRCS+=	pidfile.c
MAN=	hastmon.8 hastmon.conf.5

BINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/man
CFLAGS+=-g -O0
CFLAGS+=-I${.CURDIR}
CFLAGS+=-DINET
.if "${MK_INET6_SUPPORT}" != "no"
CFLAGS+=-DINET6
.endif
# This is needed to have WARNS > 1.
CFLAGS+=-DYY_NO_UNPUT

LDADD= -lpthread
.if "${MK_OPENSSL}" != "no"
LDADD+=	-lcrypto
CFLAGS+=-DHAVE_CRYPTO
.endif

YFLAGS+=-d
YFLAGS+=-v

CLEANFILES=y.tab.c y.tab.h y.output _*

.include <mkc.own.mk>
.include <mkc.prog.mk>
