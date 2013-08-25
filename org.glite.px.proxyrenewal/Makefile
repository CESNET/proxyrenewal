# Copyright (c) Members of the EGEE Collaboration. 2004-2010.
# See http://www.eu-egee.org/partners/ for details on the copyright
# holders.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# defaults
top_srcdir=..
builddir=build
top_builddir=${top_srcdir}/${builddir}
stagedir=.
distdir=.
globalprefix=glite
lbprefix=lb
package=glite-px-proxyrenewal
version=0.0.0
PREFIX=/opt/glite
libdir=lib
prefix=
sysconfdir=/etc
sysroot=

glite_location=${PREFIX}${prefix}
globus_prefix=/opt/globus
voms_prefix=${glite_location}

default: all

-include Makefile.inc
-include ${top_srcdir}/project/version.properties

version=${module.version}

VPATH:=${top_srcdir}/src:${top_srcdir}/examples

SOURCES=\
	config/glite-px config/setup config/startup config/systemd.* \
	doc/*.sh \
	examples/*.c interface/*.h \
	project/.post* project/.pre* project/doc_proxyrenewal.pl \
	src/*.1 src/*.8 src/*.c src/*.h \
	Makefile README
SOURCES_EXEC=config/setup config/startup doc/*.sh project/doc_proxyrenewal.pl

ifeq ($(os_type),debian)
sysdefaultdir=${sysconfdir}/default
else
sysdefaultdir=${sysconfdir}/sysconfig
endif

ifeq ($(os_type),fedora)
unitdir=`pkg-config systemd --variable=systemdsystemunitdir`
endif

GLOBUS_NOTHR_INC:= -I${globus_prefix}/include/${nothrflavour}
GLOBUS_THR_INC:= -I${globus_prefix}/include/${thrflavour}
GLOBUS_NOTHR_LIBS:=-L${globus_prefix}/lib \
	-lglobus_common_${nothrflavour}
GLOBUS_THR_LIBS:=-L${globus_prefix}/lib \
	-lglobus_common_${thrflavour}

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

CFLAGS:= ${DEBUG} \
	${VOMS_CFLAGS} \
	-I${top_srcdir}/src -I${top_srcdir}/interface \
	-I${glite_location}/include \
	 -DLOCAL_PX_COMPILE=1 ${CFLAGS}

offset=0
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
MAN1_GZ:=glite-proxy-renew.1.gz
MAN8_GZ:=glite-proxy-renewd.8.gz
MAN_GZ = ${MAN1_GZ} ${MAN8_GZ}
MAN = $(MAN_GZ:.gz=)
SCRIPTS=glite-px setup startup

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
default_libvoms=${VOMS_LIBS}
GLOBUS_EXTRA_LIBS=-lglobus_gsi_proxy_core -lglobus_gsi_credential \
	-lglobus_gsi_cert_utils -lglobus_common
else
lib_LTLIBRARIES=${NOTHRLIB} ${THRLIB} ${LIB_CORE_NOTHR}
default_libcore=${LIB_CORE_NOTHR}
default_lib=${NOTHRLIB}
default_libvoms=${VOMS_LIBS_NOTHR}
GLOBUS_EXTRA_LIBS=-lglobus_gsi_proxy_core_${nothrflavour} \
	-lglobus_gsi_credential_${nothrflavour} \
	-lglobus_gsi_cert_utils_${nothrflavour} \
	-lglobus_common_${nothrflavour}
endif

DAEMON:=glite-proxy-renewd
CLIENT:=glite-proxy-renew
EXAMPLES := renew_core

compile all: ${SCRIPTS} ${lib_LTLIBRARIES} ${DAEMON} ${CLIENT} ${MAN_GZ}

${SCRIPTS}: ${top_srcdir}/config/glite-px ${top_srcdir}/config/startup ${top_srcdir}/config/setup
	glite_var="${localstatedir}/glite"; \
	if echo "${localstatedir}" | grep 'glite'>/dev/null; then \
		glite_var="${localstatedir}"; \
	fi; \
	sed -e 's:@glite_prefix@:${sysroot}${prefix}:' -e 's:@glite_etc@:${sysroot}${sysconfdir}:' -e "s:@glite_var@:$$glite_var:" -e 's:@defaultdir@:${sysdefaultdir}:g' ${top_srcdir}/config/$@ > $@
ifneq ($(os_type),debian)
	sed -i 's/# \(Default-Start\|Default-Stop\):.*/# \1:/' $@
endif
	sed "s/^@$(os_type)@//" $@ > $@.tmp
	grep -v '^@' $@.tmp > $@
	rm $@.tmp
	chmod +x $@

ifeq (${thrflavour},)
${LIB}: ${LIBOBJ}
	${LINK} ${version_info} -o $@ ${LIBLOBJ} -rpath ${prefix}/${libdir}

${LIB_CORE}: ${LIB_CORE_OBJS}
	${LINK} ${version_info} -o $@ ${LIB_CORE_LOBJS} -rpath ${prefix}/${libdir} ${MYPROXY_LIBS} ${VOMS_LIBS} ${GLOBUS_GSSAPI_GSI_LIBS} -lglobus_gsi_proxy_core
else
${NOTHRLIB}: ${LIBOBJ}
	${LINK} ${version_info} -o $@ ${LIBLOBJ} -rpath ${prefix}/${libdir}

${THRLIB}: ${THRLIBOBJ}
	${LINK} ${version_info} -o $@ ${THRLIBLOBJ} -rpath ${prefix}/${libdir}

${LIB_CORE_NOTHR}: ${LIB_CORE_OBJS}
	${LINK} ${version_info} -o $@ ${LIB_CORE_LOBJS} -rpath ${prefix}/${libdir} ${MYPROXY_LIB_NOTHR} ${VOMS_LIBS_NOTHR} ${GLOBUS_NOTHR_LIBS} -lglobus_gsi_proxy_core_${nothrflavour}

${LIB_CORE_THR}: ${LIB_CORE_THR_OBJS}
	${LINK} ${version_info} -o $@ ${LIB_CORE_THR_LOBJS} -rpath ${prefix}/${libdir} ${MYPROXY_LIB_THR} ${VOMS_LIBS_THR} ${GLOBUS_THR_LIBS} -lglobus_gsi_proxy_core_${thrflavour}
endif

${DAEMON}: ${DAEMONOBJ} ${default_libcore}
	${LINK} -o $@ ${DAEMONOBJ} ${default_libcore} ${default_libvoms} ${GLOBUS_GSSAPI_GSI_LIBS} ${GLOBUS_EXTRA_LIBS}

${CLIENT}: ${CLIENTOBJ} ${default_lib}
	${LINK} -o $@ ${CLIENTOBJ} ${default_lib} ${GLOBUS_GSSAPI_GSI_LIBS}

${THRLIBOBJ} ${LIB_CORE_THR_OBJS}: %.thr.o: %.c
	${COMPILE} ${MYPROXY_THR_INC} ${GLOBUS_THR_INC} -o $@ -c $<

%.o: %.c
	${COMPILE} ${MYPROXY_CFLAGS} ${GLOBUS_GSSAPI_GSI_CFLAGS} -c $<

${EXAMPLES}: %: %.o
	${LINK} -o $@ $< ${default_libcore}

%.1.gz: %.1
	gzip -9 -f -c $< > $@

%.8.gz: %.8
	gzip -9 -f -c $< > $@

stage: compile
	$(MAKE) install PREFIX=${stagedir} staging=1

check:
	echo No unit tests

examples: ${EXAMPLES}

install:
	-mkdir -p ${DESTDIR}${PREFIX}${prefix}/bin ${DESTDIR}${PREFIX}${prefix}/sbin ${DESTDIR}${PREFIX}${prefix}/${libdir} ${DESTDIR}${PREFIX}${prefix}/include/glite/security/proxyrenewal ${DESTDIR}${PREFIX}${prefix}/share/man/man1 ${DESTDIR}${PREFIX}${prefix}/share/man/man8 ${DESTDIR}${PREFIX}${sysdefaultdir} ${DESTDIR}${PREFIX}${prefix}/share/doc/${package}-${version}
	${INSTALL} -m 755 ${lib_LTLIBRARIES} ${DESTDIR}${PREFIX}${prefix}/${libdir}
	${INSTALL} -m 755 ${DAEMON} ${CLIENT} ${DESTDIR}${PREFIX}${prefix}/bin
	${INSTALL} -m 755 setup ${DESTDIR}${PREFIX}${prefix}/sbin/glite-proxy-setup
	cd ${top_srcdir}/interface && ${INSTALL} -m 644 renewal.h renewal_core.h ${DESTDIR}${PREFIX}${prefix}/include/glite/security/proxyrenewal
	${INSTALL} -m 644 ${MAN1_GZ} ${DESTDIR}${PREFIX}${prefix}/share/man/man1
	${INSTALL} -m 644 ${MAN8_GZ} ${DESTDIR}${PREFIX}${prefix}/share/man/man8
	${INSTALL} -m 644 glite-px ${DESTDIR}${PREFIX}${prefix}/share/doc/${package}-${version}/glite-px
	${INSTALL} -m 644 glite-px ${DESTDIR}${PREFIX}${sysdefaultdir}
ifeq ($(os_type),fedora)
	mkdir -p ${DESTDIR}${PREFIX}${unitdir}
	${INSTALL} -m 644 ${top_srcdir}/config/systemd.proxy-renewd ${DESTDIR}${PREFIX}${unitdir}/glite-proxy-renewd.service
else
	mkdir -p ${DESTDIR}${PREFIX}${sysconfdir}/init.d
	${INSTALL} -m 755 startup ${DESTDIR}${PREFIX}${sysconfdir}/init.d/glite-proxy-renewald
endif

clean:
	$(RM) ${lib_LTLIBRARIES} $(DAEMON) $(CLIENT) $(EXAMPLES) *.o *.lo core ${SCRIPTS}
	$(RM) ${MAN1_GZ} ${MAN8_GZ}
	$(RM) -rf .libs
	$(RM) -rvf dist ${package}-*.tar.gz

distclean:
	rm -rvf project/changelog Makefile.inc *.spec debian/

.PHONY: default all compile examples check stage install clean distclean dist distcheck
