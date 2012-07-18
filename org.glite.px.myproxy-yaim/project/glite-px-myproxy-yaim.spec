Summary: @SUMMARY@
Name: glite-px-myproxy-yaim
Version: @MAJOR@.@MINOR@.@REVISION@
Release: @AGE@%{?dist}
Url: @URL@
License: ASL 2.0
Vendor: EMI
Group: Development/Tools
BuildArch: noarch
Requires: glite-yaim-bdii
Requires: glite-yaim-core
Obsoletes: glite-yaim-myproxy <= 4.0.4-2
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
AutoReqProv: yes
Source: http://eticssoft.web.cern.ch/eticssoft/repository/emi/@MODULE@/%{version}/src/%{name}-@VERSION@.src.tar.gz


%description
@DESCRIPTION@


%prep
%setup -q


%build
/usr/bin/perl ./configure --thrflavour= --nothrflavour= --root=/ --prefix=/usr --libdir=%{_lib} --project=emi --module px.myproxy-yaim
make


%check
make check


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root)
%dir /opt/glite/
%dir /opt/glite/man/
%dir /opt/glite/man/man1/
%dir /opt/glite/release/
%dir /opt/glite/release/glite-PX/
%dir /opt/glite/yaim/
%dir /opt/glite/yaim/defaults/
%dir /opt/glite/yaim/etc/
%dir /opt/glite/yaim/etc/versions/
%dir /opt/glite/yaim/examples/siteinfo/services/
%dir /opt/glite/yaim/functions/
%dir /opt/glite/yaim/node-info.d/
/opt/glite/man/man1/*
/opt/glite/release/glite-PX/COPYRIGHT
/opt/glite/release/glite-PX/LICENSE
/opt/glite/release/glite-PX/arch
/opt/glite/release/glite-PX/node-version
/opt/glite/release/glite-PX/service
/opt/glite/release/glite-PX/update
/opt/glite/yaim/etc/versions/glite-px-myproxy-yaim
/opt/glite/yaim/examples/siteinfo/services/glite-px
/opt/glite/yaim/defaults/glite-px.pre
/opt/glite/yaim/functions/config_gip_px
/opt/glite/yaim/functions/config_info_service_px
/opt/glite/yaim/functions/config_proxy_server
/opt/glite/yaim/node-info.d/glite-px


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@%{?dist}
- automatically generated package
