# $FreeBSD$

PROJECTNAME=	hastmon

CLEANFILES=	_*

SUBPRJ+=	hastmon
SUBPRJ+=	hastmonctl
SUBPRJ+=	etc

MKC_REQD=	0.20.0

.include <mkc.own.mk>
.include "version.mk"
.include <mkc.subdir.mk>