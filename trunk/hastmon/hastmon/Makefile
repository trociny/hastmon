PREFIX?=	/usr/local

MKC_CHECK_HEADERS+=	pthread_np.h
MKC_CHECK_FUNCS1+=	pthread_mutex_isowned_np:pthread_np.h

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
CFLAGS+=-I${.CURDIR}
CFLAGS+=-DINET
.if "${MK_INET6_SUPPORT}" != "no"
CFLAGS+=-DINET6
.endif
# This is needed to have WARNS > 1.
CFLAGS+=-DYY_NO_UNPUT

DPADD=	${LIBGEOM} ${LIBBSDXML} ${LIBSBUF} ${LIBL} ${LIBPTHREAD} ${LIBUTIL}
LDADD=	-lbsdxml -lsbuf -ll -lpthread
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
