Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:	0.0.2
Release:    1.1
Group:      System/Security
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: packaging/libprivilege-control.manifest 
BuildRequires:  cmake
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(security-server)
Requires: setup

%description
development package of library to control privilege of in-house application

%package devel
Summary:    Control privilege of application (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Library to control privilege of application (devel)

%package conf
Summary:    Control privilege of application files 
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description conf
Library to control privilege of application files


%prep
%setup -q

%build
cp %{SOURCE1001} .
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?_smp_mflags}

%install
%make_install

# Add symlinks for apps that are looking in /opt
ln -sf ../../etc/group %{buildroot}/opt/etc/group
ln -sf ../../etc/passwd %{buildroot}/opt/etc/passwd


# FIXME: should split to separate binaries package
%files
%manifest libprivilege-control.manifest
%{_bindir}/debug-util
%{_bindir}/kill_app
%{_bindir}/slp-su
%{_libdir}/*.so.*
%{_libdir}/udev/rules.d/95-permissions-slp.rules
%{_datadir}/privilege-control/*

%files conf
%manifest libprivilege-control.manifest
/opt/etc/group
/opt/etc/passwd

%files devel
%manifest libprivilege-control.manifest
%{_includedir}/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
