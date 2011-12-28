Summary: Virtual package with runtime and development files of gLite proxyrenewal
Name: glite-px-proxyrenewal
Version: @MAJOR@.@MINOR@.@REVISION@
Release: @AGE@%{?dist}
Url: @URL@
License: Apache Software License
Vendor: EMI
Group: Development/Libraries
BuildRequires: chrpath
BuildRequires: globus-gssapi-gsi-devel%{?_isa}
BuildRequires: libtool
BuildRequires: myproxy-devel%{?_isa}
BuildRequires: voms-devel%{?_isa}
Requires: %{name}-devel%{?_isa}
Requires: %{name}-clients
Obsoletes: glite-security-proxyrenewal%{?_isa} <= 1.3.11-4
Provides: %{name}%{?_isa} = %{version}-%{release}
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
AutoReqProv: yes
Source: http://eticssoft.web.cern.ch/eticssoft/repository/emi/@MODULE@/%{version}/src/%{name}-@VERSION@.src.tar.gz


%description
This is a virtual package providing runtime and development files for gLite
proxyrenewal.


%package libs
Summary: @SUMMARY@
Group: System Environment/Libraries
Obsoletes: glite-security-proxyrenewal%{?_isa} <= 1.3.11-4


%description libs
@DESCRIPTION@


%package devel
Summary: Development files for gLite proxyrenewal library
Group: Development/Libraries
Requires: %{name}-libs%{?_isa} = %{version}-%{release}
Obsoletes: glite-security-proxyrenewal%{?_isa} <= 1.3.11-4


%description devel
This package contains development libraries and header files for gLite
proxyrenewal library.


%package clients
Summary: gLite proxyrenewal daemon and client
Group: System Environment/Base


%description clients
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
find $RPM_BUILD_ROOT -name '*.la' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*.a' -exec rm -rf {} \;
find $RPM_BUILD_ROOT -name '*' -print | xargs -I {} -i bash -c "chrpath -d {} > /dev/null 2>&1" || echo 'Stripped RPATH'


%clean
rm -rf $RPM_BUILD_ROOT


%post libs -p /sbin/ldconfig


%postun libs -p /sbin/ldconfig


%pre clients
getent group glite >/dev/null || groupadd -r glite
getent passwd glite >/dev/null || useradd -r -g glite -d /var/glite -c "gLite user" glite
mkdir -p /var/glite /var/log/glite 2>/dev/null || :
chown glite:glite /var/glite /var/log/glite
exit 0


%post clients
/sbin/chkconfig --add glite-proxy-renewald


%preun clients
if [ $1 -eq 0 ] ; then
	/sbin/service glite-proxy-renewald stop >/dev/null 2>&1
	/sbin/chkconfig --del glite-proxy-renewald
fi


%postun clients
if [ "$1" -ge "1" ] ; then
	/sbin/service glite-proxy-renewald condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root)


%files libs
%defattr(-,root,root)
%dir /usr/share/doc/%{name}-%{version}/
/usr/share/doc/%{name}-%{version}/LICENSE
/usr/%{_lib}/libglite_security_proxyrenewal.so.2.@MINOR@.@REVISION@
/usr/%{_lib}/libglite_security_proxyrenewal.so.2
/usr/%{_lib}/libglite_security_proxyrenewal_core.so.2.@MINOR@.@REVISION@
/usr/%{_lib}/libglite_security_proxyrenewal_core.so.2


%files devel
%defattr(-,root,root)
%dir /usr/include/glite/
%dir /usr/include/glite/security/
%dir /usr/include/glite/security/proxyrenewal/
/usr/include/glite/security/proxyrenewal/*.h
/usr/%{_lib}/libglite_security_proxyrenewal.so
/usr/%{_lib}/libglite_security_proxyrenewal_core.so


%files clients
%defattr(-,root,root)
/etc/init.d/glite-proxy-renewald
/usr/bin/glite-proxy-renew
/usr/bin/glite-proxy-renewd
/usr/share/man/man1/glite-proxy-renew.1.gz
/usr/share/man/man8/glite-proxy-renewd.8.gz


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@%{?dist}
- automatically generated package

