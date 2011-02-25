#
# Copyright (c) 2004 on behalf of the EU EGEE Project:
# The European Organization for Nuclear Research (CERN),
# Istituto Nazionale di Fisica Nucleare (INFN), Italy
# Datamat Spa, Italy
# Centre National de la Recherche Scientifique (CNRS), France
# CS Systeme d'Information (CSSI), France
# Royal Institute of Technology, Center for Parallel Computers (KTH-PDC), Sweden
# Universiteit van Amsterdam (UvA), Netherlands
# University of Helsinki (UH.HIP), Finland
# University of Bergen (UiB), Norway
# Council for the Central Laboratory of the Research Councils (CCLRC), United Kingdom
#
# Top Makefile file for the GLite Security Proxyrenewal module
#
# Authors: Ales Krenek <ljocha@ics.muni.cz>
# Version info: $Id$
# Release: $Name$
#
# Revision history:
# $Log
#

# defaults
top_srcdir=..
builddir=build
top_builddir=${top_srcdir}/${builddir}
stagedir=.
distdir=.
globalprefix=glite
lbprefix=lb
package=glite-security-proxyrenewal
version=0.0.0
PREFIX=/opt/glite
libdir=lib
prefix=
sysconfdir=/opt/glite/etc

glite_location=${PREFIX}${prefix}
globus_prefix=/opt/globus

-include Makefile.inc

VPATH:=${top_srcdir}/src:${top_srcdir}/examples

GLOBUS_NOTHR_INC:= -I${globus_prefix}/include/${nothrflavour}
GLOBUS_THR_INC:= -I${globus_prefix}/include/${thrflavour}
GLOBUS_NOTHR_LIBS:=-L${globus_prefix}/lib \
	-lglobus_common_${nothrflavour} \
	-lssl

myproxy_prefix=${myproxy-devel_prefix}
myproxy_prefix?=${globus_prefix}

MYPROXY_NOTHR_INC:= -I${myproxy_prefix}/include/${nothrflavour}
MYPROXY_THR_INC:= -I${myproxy_prefix}/include/${thrflavour}

MYPROXY_LIB_NOTHR :=-L${myproxy_prefix}/${libdir} -L${myproxy_prefix}/lib -lmyproxy_${nothrflavour}
MYPROXY_LIB_THR:=-L${myproxy_prefix}/${libdir} -L${myproxy_prefix}/lib -lmyproxy_${thrflavour}

VOMS_CFLAGS?=-I${voms_prefix}/include -I${voms_prefix}/include/glite/security
VOMS_LIBS?=-L${voms_prefix}/${libdir} -lvomsapi
VOMS_LIBS_NOTHR := -L${voms_prefix}/${libdir} -lvomsapi_${nothrflavour}
VOMS_LIBS_THR := -L${voms_prefix}/${libdir} -lvomsapi_${thrflavour}

GLOBUS_GSSAPI_GSI_CFLAGS?=${GLOBUS_NOTHR_INC}
GLOBUS_GSSAPI_GSI_LIBS?=${GLOBUS_NOTHR_LIBS}

MYPROXY_CFLAGS?=${MYPROXY_NOTHR_INC}
MYPROXY_LIBS?=${MYPROXY_LIB_NOTHR}

DEBUG:=-g -O0

CFLAGS:= ${CFLAGS} ${DEBUG} \
	${VOMS_CFLAGS} \
	-I${top_srcdir}/src -I${top_srcdir}/interface \
	-I${glite_location}/include

offset=1
version_info:=-version-info ${shell \
	perl -e '$$,=":"; @F=split "\\.","${version}"; print $$F[0]+$$F[1]+${offset},$$F[2],$$F[1]' }

CC:=gcc
COMPILE:=libtool --mode=compile ${CC} ${CFLAGS}
LINK:=libtool --mode=link ${CC} ${LDFLAGS}
INSTALL:=libtool --mode=install install

DAEMONOBJ:=renewd.o renew.o common.o commands.o api.o voms.o
LIBOBJ:=api.o common.o
LIB_CORE_OBJS := renewal_core.o voms.o
CLIENTOBJ:=client.o

THRLIBOBJ:=${LIBOBJ:.o=.thr.o}
LIBLOBJ:=${LIBOBJ:.o=.lo}
THRLIBLOBJ:=${LIBOBJ:.o=.thr.lo}

LIB_CORE_LOBJS := ${LIB_CORE_OBJS:.o=.lo}
LIB_CORE_THR_OBJS := ${LIB_CORE_OBJS:.o=.thr.o}
LIB_CORE_THR_LOBJS := ${LIB_CORE_OBJS:.o=.thr.lo}

LIB:=libglite_security_proxyrenewal.la
NOTHRLIB:=libglite_security_proxyrenewal_${nothrflavour}.la
THRLIB:=libglite_security_proxyrenewal_${thrflavour}.la
LIB_CORE := libglite_security_proxyrenewal_core.la
LIB_CORE_NOTHR := libglite_security_proxyrenewal_core_${nothrflavour}.la
LIB_CORE_THR := libglite_security_proxyrenewal_core_${thrflavour}.la

ifeq (${thrflavour},)
lib_LTLIBRARIES=${LIB} ${LIB_CORE}
default_libcore=${LIB_CORE}
default_lib=${LIB}
else
lib_LTLIBRARIES=${NOTHRLIB} ${THRLIB} ${LIB_CORE_NOTHR}
default_libcore=${LIB_CORE_NOTHR}
default_lib=${NOTHRLIB}
endif

DAEMON:=glite-proxy-renewd
CLIENT:=glite-proxy-renew
EXAMPLES := renew_core

default: all
compile all: ${lib_LTLIBRARIES} ${DAEMON} ${CLIENT} 

ifeq (${thrflavour},)
${LIB}: ${LIBOBJ}
	${LINK} ${version_info} -o $@ ${LIBLOBJ} -rpath ${glite_location}/${libdir}

${LIB_CORE}: ${LIB_CORE_OBJS}
	${LINK} ${version_info} -o $@ ${LIB_CORE_LOBJS} -rpath ${glite_location}/${libdir} ${MYPROXY_LIBS} ${VOMS_LIBS}
else
${NOTHRLIB}: ${LIBOBJ}
	${LINK} ${version_info} -o $@ ${LIBLOBJ} -rpath ${glite_location}/${libdir}

${THRLIB}: ${THRLIBOBJ}
	${LINK} ${version_info} -o $@ ${THRLIBLOBJ} -rpath ${glite_location}/${libdir}

${LIB_CORE_NOTHR}: ${LIB_CORE_OBJS}
	${LINK} ${version_info} -o $@ ${LIB_CORE_LOBJS} -rpath ${glite_location}/${libdir} ${MYPROXY_LIB_NOTHR} ${VOMS_LIBS_NOTHR}

${LIB_CORE_THR}: ${LIB_CORE_THR_OBJS}
	${LINK} ${version_info} -o $@ ${LIB_CORE_THR_LOBJS} -rpath ${glite_location}/${libdir} ${MYPROXY_LIB_THR} ${VOMS_LIBS_THR}
endif

${DAEMON}: ${DAEMONOBJ} ${default_libcore}
	${LINK} -o $@ ${DAEMONOBJ} ${default_libcore}

${CLIENT}: ${CLIENTOBJ} ${default_lib}
	${LINK} -o $@ ${CLIENTOBJ} ${default_lib} ${GLOBUS_GSSAPI_GSI_LIBS}

${THRLIBOBJ} ${LIB_CORE_THR_OBJS}: %.thr.o: %.c
	${COMPILE} ${MYPROXY_THR_INC} ${GLOBUS_THR_INC} -o $@ -c $<

%.o: %.c
	${COMPILE} ${MYPROXY_CFLAGS} ${GLOBUS_GSSAPI_GSI_CFLAGS} -c $<

${EXAMPLES}: %: %.o
	${LINK} -o $@ $< ${default_libcore}

stage: compile
	$(MAKE) install PREFIX=${stagedir}

check:
	echo No unit tests

examples: ${EXAMPLES}

dist: distsrc distbin

distsrc:
	mkdir -p ${top_srcdir}/${package}-${version}
	cd ${top_srcdir} && GLOBIGNORE="${package}-${version}" && cp -Rf * ${package}-${version}
	cd ${top_srcdir} && tar -czf ${distdir}/${package}-${version}_src.tar.gz --exclude-from=project/tar_exclude ${package}-${version}
	rm -rf ${top_srcdir}/${package}-${version}

distbin:
	$(MAKE) install PREFIX=`pwd`/tmpbuilddir
	cd tmpbuilddir && tar -czf ../${top_srcdir}/${distdir}/${package}-${version}_bin.tar.gz *
	rm -rf tmpbuilddir

install:
	-mkdir -p ${DESTDIR}${PREFIX}${prefix}/bin ${DESTDIR}${PREFIX}${prefix}/${libdir} ${DESTDIR}${PREFIX}${prefix}/include/glite/security/proxyrenewal ${DESTDIR}${PREFIX}${prefix}/share/doc/${package}-${version} ${DESTDIR}${PREFIX}${sysconfdir}/init.d
	${INSTALL} -m 755 ${lib_LTLIBRARIES} ${DESTDIR}${PREFIX}${prefix}/${libdir}
	${INSTALL} -m 755 ${DAEMON} ${CLIENT} ${DESTDIR}${PREFIX}${prefix}/bin
	${INSTALL} -m 644 ${top_srcdir}/LICENSE ${DESTDIR}${PREFIX}${prefix}/share/doc/${package}-${version}
	cd ${top_srcdir}/interface && ${INSTALL} -m 644 renewal.h renewal_core.h ${DESTDIR}${PREFIX}${prefix}/include/glite/security/proxyrenewal
	${INSTALL} -m 755 ${top_srcdir}/config/startup ${DESTDIR}${PREFIX}${sysconfdir}/init.d/glite-proxy-renewald


clean:
	$(RM) ${lib_LTLIBRARIES} $(DAEMON) $(CLIENT) $(EXAMPLES) *.o *.lo core 

.PHONY: default all compile examples check stage dist distsrc distbin install clean
