Name:           glite-px-proxyrenewal
Version:        @MAJOR@.@MINOR@.@REVISION@
Release:        @AGE@%{?dist}
Summary:        Virtual package with run-time and development files of gLite proxyrenewal

Group:          Development/Libraries
License:        ASL 2.0
Url:            @URL@
Vendor:         EMI
Source:         http://eticssoft.web.cern.ch/eticssoft/repository/emi/@MODULE@/%{version}/src/%{name}-@VERSION@.src.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  chrpath
BuildRequires:  globus-gssapi-gsi-devel%{?_isa}
BuildRequires:  libtool
BuildRequires:  myproxy-devel%{?_isa}
BuildRequires:  pkgconfig
BuildRequires:  voms-devel%{?_isa}
Requires:       %{name}-devel%{?_isa}
Requires:       %{name}-progs
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
/usr/bin/perl ./configure --thrflavour= --nothrflavour= --root=/ --prefix=/usr --libdir=%{_lib} --project=emi --module px.proxyrenewal
make


%check
make check


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
sed -i 's,\(lockfile=/var/lock\),\1/subsys,' $RPM_BUILD_ROOT/etc/init.d/glite-proxy-renewald
find $RPM_BUILD_ROOT -name '*.la' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*.a' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*' -print | xargs -I {} -i bash -c "chrpath -d {} > /dev/null 2>&1" || echo 'Stripped RPATH'


%clean
rm -rf $RPM_BUILD_ROOT


%post libs -p /sbin/ldconfig


%postun libs -p /sbin/ldconfig


%pre progs
getent group glite >/dev/null || groupadd -r glite
getent passwd glite >/dev/null || useradd -r -g glite -d /var/glite -c "gLite user" glite
mkdir -p /var/glite /var/log/glite 2>/dev/null || :
chown glite:glite /var/glite /var/log/glite
exit 0


%post progs
/sbin/chkconfig --add glite-proxy-renewald
if [ $1 -eq 1 ] ; then
	/sbin/chkconfig glite-proxy-renewald off
fi


%preun progs
if [ $1 -eq 0 ] ; then
	/sbin/service glite-proxy-renewald stop >/dev/null 2>&1
	/sbin/chkconfig --del glite-proxy-renewald
fi


%postun progs
if [ "$1" -ge "1" ] ; then
	/sbin/service glite-proxy-renewald condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root)

%files libs
%defattr(-,root,root)
%dir /usr/share/doc/%{name}-%{version}/
/usr/share/doc/%{name}-%{version}/LICENSE
%{_libdir}/libglite_security_proxyrenewal.so.*
%{_libdir}/libglite_security_proxyrenewal_core.so.*

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
/etc/init.d/glite-proxy-renewald
%{_bindir}/glite-proxy-renew
%{_bindir}/glite-proxy-renewd
/usr/share/man/man1/glite-proxy-renew.1.gz
/usr/share/man/man8/glite-proxy-renewd.8.gz


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@%{?dist}
- automatically generated package

