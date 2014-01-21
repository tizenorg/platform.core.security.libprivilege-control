Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.43.TIZEN
Release:    1
Group:      Security/Access Control
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001:    %{name}.manifest
BuildRequires: cmake
BuildRequires: libcap-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(libiri)
BuildRequires: pkgconfig(sqlite3)

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
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

export CFLAGS="${CFLAGS} -Wno-implicit-function-declaration"
%cmake . -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
         -DCMAKE_VERBOSE_MAKEFILE=ON

VERBOSE=1 make %{?jobs:-j%jobs}

%install
%make_install
mkdir -p %{buildroot}/usr/share/privilege-control/

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/smack-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service

%post
/sbin/ldconfig
/usr/share/privilege-control/db/updater.sh

%postun -p /sbin/ldconfig

api_feature_loader --verbose --dir=/usr/share/privilege-control/
api_feature_loader --verbose --rules=/usr/share/privilege-control/ADDITIONAL_RULES.smack

%check
./db/updater.sh --check-files %{buildroot}

%files
%manifest %{name}.manifest
%license LICENSE
%{_libdir}/*.so.*
%{_bindir}/slp-su
%{_libdir}/librules-db-sql-udf.so
#systemd service
/usr/lib/systemd/system/smack-rules.service
/usr/bin/api_feature_loader
#link to activate systemd service
/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
/usr/share/privilege-control/db/rules-db.sql
/usr/share/privilege-control/db/rules-db-data.sql
/usr/share/privilege-control/db/updater.sh
/usr/share/privilege-control/db/updates/*
/usr/share/privilege-control/db/load-rules-db.sql

%files conf
%manifest %{name}.manifest
/opt/dbspace/.privilege_control*.db

%files devel
%manifest %{name}.manifest
%{_includedir}/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
