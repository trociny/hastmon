.PATH:	${.CURDIR}/../hastmon

PREFIX?=	/usr/local

MKC_COMMON_DEFINES.Linux=	-D_NO_SO_LEN

MKC_CHECK_HEADERS+=	pthread_np.h
MKC_CHECK_FUNCS1+=	pthread_mutex_isowned_np:pthread_np.h

MKC_CHECK_HEADERS+=	machine/vmparam.h sys/user.h
MKC_CHECK_HEADERS+=	sys/endian.h

MKC_CHECK_DEFINES+=	TAILQ_FOREACH_SAFE:sys/queue.h

MKC_CHECK_FUNCS3=	strlcat:string.h strlcpy:string.h
MKC_SOURCE_FUNCLIBS=	strlcat strlcpy

PROG=	hastmonctl
SRCS+=	ebuf.c
SRCS+=	hast_proto.c hastmonctl.c
SRCS+=	nv.c
SRCS+=	parse.y pjdlog.c
SRCS+=	proto.c proto_common.c proto_tcp4.c proto_uds.c
SRCS+=	token.l
SRCS+=	subr.c
SRCS+=	y.tab.h
SRCS+=	auth.c
MAN=	hastmonctl.8

BINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/man
CFLAGS+=-g -O0
CFLAGS+=-I${.CURDIR}/../hastmon
CFLAGS+=-DINET
.if "${MK_INET6_SUPPORT}" != "no"
CFLAGS+=-DINET6
.endif
# This is needed to have WARNS > 1.
CFLAGS+=-DYY_NO_UNPUT

.if "${MK_OPENSSL}" != "no"
LDADD+=	-lcrypto
CFLAGS+=-DHAVE_CRYPTO
.endif

YFLAGS+=-d
YFLAGS+=-v

CLEANFILES=y.tab.c y.tab.h y.output _*

.include <mkc.own.mk>
.include <mkc.prog.mk>
