Summary: @SUMMARY@
Name: emi-px
Version: @MAJOR@.@MINOR@.@REVISION@
Release: @AGE@%{?dist}
Url: @URL@
License: Apache Software License
Vendor: EMI
Group: System Environment/Base
Requires: bdii
Requires: emi-version
Requires: fetch-crl
Requires: glite-px-myproxy-yaim
Requires: myproxy-server
Requires: myproxy-admin
#Requires: glue-service-provider
Requires: glite-info-provider-service
Requires: glue-schema
Obsoletes: glite-PX <= 3.2.2-3
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
AutoReqProv: yes
Source: http://eticssoft.web.cern.ch/eticssoft/repository/emi/@MODULE@/%{version}/src/%{name}-@VERSION@.src.tar.gz


%description
@DESCRIPTION@


%prep
%setup -q


%build


%check


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@%{?dist}
- automatically generated package
