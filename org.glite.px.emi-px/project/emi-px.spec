# virtual package
%global debug_package %{nil}

Name:           emi-px
Version:        @MAJOR@.@MINOR@.@REVISION@
Release:        @AGE@%{?dist}
Summary:        @SUMMARY@

Group:          System Environment/Base
License:        ASL 2.0
URL:            @URL@
Vendor:         EMI
Source:         http://eticssoft.web.cern.ch/eticssoft/repository/emi/@MODULE@/%{version}/src/%{name}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

Requires:       bdii
Requires:       emi-version
Requires:       fetch-crl
Requires:       glite-px-myproxy-yaim
Requires:       myproxy-server
Requires:       myproxy-admin
#Requires: glue-service-provider
Requires:       glite-info-provider-service
Requires:       glue-schema
Obsoletes:      glite-PX <= 3.2.2-3

%description
@DESCRIPTION@


%prep
%setup -q


%build


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files


%changelog
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@
- automatically generated package
