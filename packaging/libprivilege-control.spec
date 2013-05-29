Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.27.TIZEN
Release:    1
Group:      Security/Access Control
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source2:    smack-default-labeling.service
Source1001:    %{name}.manifest
BuildRequires: cmake
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(dlog)

%description
development package of library to control privilege of in-house application

%package devel
Summary:    Control privilege of application (devel)
Requires:   %{name} = %{version}-%{release}

%description devel
Library to control privilege of application (devel)

%package conf
Summary:    Control privilege of application files
Requires:   %{name} = %{version}-%{release}

%description conf
Library to control privilege of application files


%prep
%setup -q
cp %{SOURCE1001} .

%build
export CFLAGS="${CFLAGS} -Wno-implicit-function-declaration"
%cmake . -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}

make %{?jobs:-j%jobs}

%install
%make_install
mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
install -m 644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/
ln -s ../smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/basic.target.wants/
mkdir -p %{buildroot}/usr/share/privilege-control/

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest %{name}.manifest
%license LICENSE
%{_libdir}/*.so.*
%{_bindir}/slp-su
%dir %{_datarootdir}/privilege-control
%{_datarootdir}/privilege-control/*

%files conf
%manifest %{name}.manifest
/opt/etc/smack/*
/usr/lib/systemd/system/smack-default-labeling.service
/usr/lib/systemd/system/basic.target.wants/smack-default-labeling.service
/opt/dbspace/.privilege_control*.db

%files devel
%manifest %{name}.manifest
%{_includedir}/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
