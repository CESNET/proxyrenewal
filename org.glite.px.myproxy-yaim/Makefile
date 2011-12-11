top_srcdir=..
stagedir=.
package=glite-px-myproxy-yaim
version=0.0.0
PREFIX=/opt/glite
yaim_prefix=
sysconfdir=/opt/glite/etc

-include Makefile.inc
-include ../project/version.properties

yaim_prefix=/opt/glite
ifeq (${project},emi)
yaim_project=/emi
endif

FILES=glite-px.pre LICENSE COPYRIGHT node-version arch service update

all ${FILES}:
	glite_var="${localstatedir}/glite"; \
	if echo "${localstatedir}" | grep 'glite'>/dev/null; then \
		glite_var="${localstatedir}"; \
	fi; \
	sed -e 's:@glite_prefix@:${sysroot}${prefix}:' -e 's:@glite_etc@:${sysconfdir}:' -e "s:@glite_var@:$$glite_var:" $(top_srcdir)/config/defaults/glite-px.pre > glite-px.pre

	# metapackage files
	echo -e "${gLiteCopyrightText}\n\n${gLiteLicenseText}" > LICENSE
	cp LICENSE COPYRIGHT
	echo ${module.version}-${module.age} > node-version
	echo ${platformArch} > arch
	echo "NA" > service
	echo "NA" > update

install: ${FILES}
	mkdir -p ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/functions/
	mkdir -p ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/node-info.d
	mkdir -p ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/examples/siteinfo/services
	mkdir -p ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/etc/versions
	mkdir -p ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/defaults
	install -m 0644 $(top_srcdir)/config/services/glite-px ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/examples/siteinfo/services/glite-px
	for c in gip_px  proxy_server ; do \
		install -m 0644 $(top_srcdir)/config/functions/config_$$c ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/functions; \
	done
	install -m 0644 $(top_srcdir)/config/functions${yaim_project}/config_info_service_px ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/functions
	install -m 0644 ${top_srcdir}/config/node-info.d${yaim_project}/glite-px ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/node-info.d; \
	install -m 0644 glite-px.pre ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/defaults
	echo "$(package) $(module.version)-$(module.age)" > ${DESTDIR}${PREFIX}${yaim_prefix}/yaim/etc/versions/$(package)
	mkdir -p ${DESTDIR}${PREFIX}${yaim_prefix}/release/glite-PX
	cp -fp LICENSE COPYRIGHT node-version arch service update ${DESTDIR}${PREFIX}${yaim_prefix}/release/glite-PX/

stage:
	$(MAKE) install PREFIX=${stagedir}

check:

clean:
	rm -rvf ${FILES}

distclean:
	rm -rvf Makefile.inc *.spec debian/

.PHONY: default all check install stage clean
