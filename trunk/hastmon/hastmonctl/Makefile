.PATH:	${.CURDIR}/../hastmon

PREFIX?=	/usr/local

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
MANDIR=${PREFIX}/man/man
CFLAGS+=-I${.CURDIR}/../hastmon
CFLAGS+=-DINET
.if "${MK_INET6_SUPPORT}" != "no"
CFLAGS+=-DINET6
.endif
# This is needed to have WARNS > 1.
CFLAGS+=-DYY_NO_UNPUT

DPADD=	${LIBL}
LDADD=	-ll
.if "${MK_OPENSSL}" != "no"
DPADD+=	${LIBCRYPTO}
LDADD+=	-lcrypto
CFLAGS+=-DHAVE_CRYPTO
.endif

YFLAGS+=-d
YFLAGS+=-v

CLEANFILES=y.tab.c y.tab.h y.output

.include <mkc.own.mk>
.include <mkc.prog.mk>
