Name: qdigidoc
Version: 3.3
Release: 1%{?dist}
Summary: DigiDoc UI applications
Group: Applications/File
License: LGPLv2+
URL: http://www.ria.ee		
Source0: qdigidoc.tar.gz
BuildRoot: %{_tmppath}/-%{version}-%{release}-root-%(%{__id_u} -n)
%if 0%{?fedora}
BuildRequires: libdigidocpp-devel, openldap-devel, qt4-devel
Requires: liberation-sans-fonts
%else
BuildRequires: openldap2-devel, libqt4-devel 
Requires: liberation-fonts
%endif
BuildRequires: libdigidocpp-devel
Requires: libdigidocpp => 3.3
%description
Qt based UI application for verifying and signing digital signatures

%if %{defined suse_version}
%debug_package
%endif

%prep
%setup -q -n %{name}
cmake . \
 -DCMAKE_BUILD_TYPE=RelWithDebInfo \
 -DCMAKE_INSTALL_PREFIX=/usr \
 -DCMAKE_VERBOSE_MAKEFILE=ON

%build
make

%install
rm -rf %{buildroot}
cd %{_builddir}/%{name}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}
cd %{_builddir}/%{name}
make clean

%files
%defattr(-,root,root,-)
%doc
%{_bindir}/*
%{_mandir}/*
%{_datadir}/applications/*
%{_datadir}/mime/packages/*
%{_datadir}/icons/hicolor/*

%changelog
* Fri Aug 13 2010 RIA <info@ria.ee> 1.0-1
- first build no changes

%post
/usr/bin/update-desktop-database &> /dev/null || :
/usr/bin/update-mime-database %{_datadir}/mime &> /dev/null || :

%postun
/usr/bin/update-desktop-database &> /dev/null || :
/usr/bin/update-mime-database %{_datadir}/mime &> /dev/null || :
