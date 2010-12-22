top_srcdir=..
stagedir=.
package=glite-px-myproxy-yaim
version=0.0.0
PREFIX=/opt/glite

-include Makefile.inc
-include ../project/version.properties

all:

install:
	mkdir -p $(PREFIX)/yaim/functions/
	mkdir -p $(PREFIX)/yaim/node-info.d
	mkdir -p $(PREFIX)/yaim/examples/siteinfo/services
	mkdir -p $(PREFIX)/yaim/etc/versions
	install -m 0644 $(top_srcdir)/config/services/glite-px $(PREFIX)/yaim/examples/siteinfo/services/glite-px
	for c in gip_px  info_service_px  proxy_server ; do \
		install -m 0644 $(top_srcdir)/config/functions/config_$$c $(PREFIX)/yaim/functions; \
	done
	install -m 0644 $(top_srcdir)/config/node-info.d/glite-px $(PREFIX)/yaim/node-info.d
	echo "$(package) $(module.version)-$(module.age)" > $(PREFIX)/yaim/etc/versions/$(package)

stage:
	$(MAKE) install PREFIX=${stagedir}

check:

clean:
	rm -rvf log.xml project/ rpmbuild/ RPMS/ tgz/ debian/

.PHONY: default all check stage clean
