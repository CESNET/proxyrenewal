top_srcdir=..
stagedir=.
package=glite-px-myproxy-yaim
version=0.0.0
PREFIX=/opt/glite
prefix=
sysconfdir=/opt/glite/etc

-include Makefile.inc
-include ../project/version.properties

all:

install:
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/yaim/functions/
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/yaim/node-info.d
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/yaim/examples/siteinfo/services
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/yaim/etc/versions
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/yaim/defaults
	install -m 0644 $(top_srcdir)/config/services/glite-px ${DESTDIR}${PREFIX}${prefix}/yaim/examples/siteinfo/services/glite-px
	for c in gip_px  info_service_px  proxy_server ; do \
		install -m 0644 $(top_srcdir)/config/functions/config_$$c ${DESTDIR}${PREFIX}${prefix}/yaim/functions; \
	done
	# dirty hack for EPEL - flavour-less globus not initialized by gpt
	if test "x$(thrflavour)" = "x"; then \
		grep -v config_globus_clients $(top_srcdir)/config/node-info.d/glite-px > glite-px; \
		install -m 0644 glite-px ${DESTDIR}${PREFIX}${prefix}/yaim/node-info.d; \
		prefix=/usr sysconfdir=/etc $(top_srcdir)/config/defaults/glite-px.pre.sh > glite-px.pre; \
	else \
		install -m 0644 $(top_srcdir)/config/node-info.d/glite-px ${DESTDIR}${PREFIX}${prefix}/yaim/node-info.d; \
		prefix=${sysrootdir}${prefix} sysconfdir=${sysconfdir} $(top_srcdir)/config/defaults/glite-px.pre.sh > glite-px.pre; \
	fi
	install -m 0644 glite-px.pre ${DESTDIR}${PREFIX}${prefix}/yaim/defaults
	echo "$(package) $(module.version)-$(module.age)" > ${DESTDIR}${PREFIX}${prefix}/yaim/etc/versions/$(package)

stage:
	$(MAKE) install PREFIX=${stagedir}

check:

clean:
	rm -rvf log.xml project/ rpmbuild/ RPMS/ tgz/ debian/

.PHONY: default all check stage clean
