Name:           glite-px-myproxy-yaim
Version:        @MAJOR@.@MINOR@.@REVISION@
Release:        @AGE@%{?dist}
Summary:        @SUMMARY@

Group:          Development/Tools
License:        ASL 2.0
URL:            @URL@
Vendor:         EMI
Source:         http://eticssoft.web.cern.ch/eticssoft/repository/emi/@MODULE@/%{version}/src/%{name}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildArch:      noarch
BuildRequires:  perl
BuildRequires:  perl(Getopt::Long)
BuildRequires:  perl(POSIX)
Requires:       glite-yaim-bdii
Requires:       glite-yaim-core
Obsoletes:      glite-yaim-myproxy <= 4.0.4-2
Provides:       glite-yaim-myproxy = %{version}-%{release}

%description
@DESCRIPTION@


%prep
%setup -q


%build
perl ./configure --thrflavour= --nothrflavour= --root=/ --prefix=%{_prefix} --libdir=%{_lib} --project=emi --module px.myproxy-yaim
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root)
%doc ChangeLog LICENSE
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
* @SPEC_DATE@ @MAINTAINER@ - @MAJOR@.@MINOR@.@REVISION@-@AGE@
- automatically generated package
