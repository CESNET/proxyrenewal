Name:           glite-px-proxyrenewal
Version:        @MAJOR@.@MINOR@.@REVISION@
Release:        @AGE@%{?dist}
Summary:        Virtual package with run-time and development files of gLite proxyrenewal

Group:          Development/Libraries
License:        ASL 2.0
Url:            @URL@
Vendor:         EMI
Source:         http://eticssoft.web.cern.ch/eticssoft/repository/emi/@MODULE@/%{version}/src/%{name}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  chrpath
BuildRequires:  globus-gssapi-gsi-devel%{?_isa}
BuildRequires:  libtool
BuildRequires:  myproxy-devel%{?_isa}
BuildRequires:  perl
BuildRequires:  perl(Getopt::Long)
BuildRequires:  perl(POSIX)
BuildRequires:  pkgconfig
BuildRequires:  voms-devel%{?_isa}
Requires:       %{name}-devel%{?_isa}
Requires:       %{name}-progs
%if 0%{?fedora}
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd
%else
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
%endif
Obsoletes:      glite-security-proxyrenewal%{?_isa} <= 1.3.11-4

%description
This is a virtual package providing run-time and development files for gLite
proxyrenewal.


%package        libs
Summary:        @SUMMARY@
Group:          System Environment/Libraries
Obsoletes:      glite-security-proxyrenewal%{?_isa} <= 1.3.11-4

%description    libs
@DESCRIPTION@


%package        devel
Summary:        Development files for gLite proxyrenewal library
Group:          Development/Libraries
Requires:       %{name}-libs%{?_isa} = %{version}-%{release}
Obsoletes:      glite-security-proxyrenewal%{?_isa} <= 1.3.11-4

%description    devel
This package contains development libraries and header files for gLite
proxyrenewal library.


%package        progs
Summary:        gLite proxyrenewal daemon and client
Group:          System Environment/Base

%description    progs
This package contains daemon and client program of gLite proxyrenewal.


%prep
%setup -q


%build
perl ./configure --thrflavour= --nothrflavour= --root=/ --prefix=%{_prefix} --libdir=%{_lib} --project=emi --module px.proxyrenewal
CFLAGS="%{?optflags}" LDFLAGS="%{?__global_ldflags}" make


%check
CFLAGS="%{?optflags}" LDFLAGS="%{?__global_ldflags}" make check


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
# documentation installed by %doc
rm -rf $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}
%if ! 0%{?fedora}
sed -i 's,\(lockfile=/var/lock\),\1/subsys,' $RPM_BUILD_ROOT/etc/init.d/glite-proxy-renewald
mkdir $RPM_BUILD_ROOT/etc/rc.d
mv $RPM_BUILD_ROOT/etc/init.d $RPM_BUILD_ROOT/etc/rc.d
%endif
find $RPM_BUILD_ROOT -name '*.la' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*.a' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*' -print | xargs -I {} -i bash -c "chrpath -d {} > /dev/null 2>&1" || echo 'Stripped RPATH'
mkdir -p $RPM_BUILD_ROOT/var/lib/glite
mkdir -p $RPM_BUILD_ROOT/var/spool/glite-renewd


%clean
rm -rf $RPM_BUILD_ROOT


%post libs -p /sbin/ldconfig


%postun libs -p /sbin/ldconfig


%pre progs
getent group glite >/dev/null || groupadd -r glite
getent passwd glite >/dev/null || useradd -r -g glite -d /var/lib/glite -c "gLite user" glite
exit 0


%post progs
%if 0%{?fedora}
if [ $1 -eq 1 ] ; then
    # Initial installation
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi
%else
/sbin/chkconfig --add glite-proxy-renewald
if [ $1 -eq 1 ] ; then
    /sbin/chkconfig glite-proxy-renewald off
fi
%endif


%preun progs
%if 0%{?fedora}
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable glite-proxy-renewd.service > /dev/null 2>&1 || :
    /bin/systemctl stop glite-proxy-renewd.service > /dev/null 2>&1 || :
fi
%else
if [ $1 -eq 0 ] ; then
    /sbin/service glite-proxy-renewald stop >/dev/null 2>&1
    /sbin/chkconfig --del glite-proxy-renewald
fi
%endif


%postun progs
%if 0%{?fedora}
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    /bin/systemctl try-restart glite-proxy-renewd.service >/dev/null 2>&1 || :
fi
%else
if [ "$1" -ge "1" ] ; then
    /sbin/service glite-proxy-renewald condrestart >/dev/null 2>&1 || :
fi
%endif


%files
%defattr(-,root,root)

%files libs
%defattr(-,root,root)
%doc LICENSE project/ChangeLog
%{_libdir}/libglite_security_proxyrenewal.so.1
%{_libdir}/libglite_security_proxyrenewal.so.1.*
%{_libdir}/libglite_security_proxyrenewal_core.so.1
%{_libdir}/libglite_security_proxyrenewal_core.so.1.*

%files devel
%defattr(-,root,root)
%dir %{_includedir}/glite/
%dir %{_includedir}/glite/security/
%dir %{_includedir}/glite/security/proxyrenewal/
%{_includedir}/glite/security/proxyrenewal/*.h
%{_libdir}/libglite_security_proxyrenewal.so
%{_libdir}/libglite_security_proxyrenewal_core.so

%files progs
%defattr(-,root,root)
%dir %attr(0755, glite, glite) %{_localstatedir}/lib/glite
%dir %attr(0700, glite, glite) %{_localstatedir}/spool/glite-renewd
%doc LICENSE project/ChangeLog README config/glite-px
%config(noreplace missingok) %{_sysconfdir}/sysconfig/glite-px
%if 0%{?fedora}
%{_unitdir}/glite-proxy-renewd.service
%else
%{_initrddir}/glite-proxy-renewald
%endif
%{_bindir}/glite-proxy-renew
%{_bindir}/glite-proxy-renewd
%{_sbindir}/glite-proxy-setup
%{_mandir}/man1/glite-proxy-renew.1.gz
%{_mandir}/man8/glite-proxy-renewd.8.gz


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@
- automatically generated package

