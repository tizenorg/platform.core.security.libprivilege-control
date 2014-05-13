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
BuildRequires: pkgconfig(libtzplatform-config)

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
         -DCMAKE_VERBOSE_MAKEFILE=ON \
	-DTZ_SYS_DB=%TZ_SYS_DB \
	-DTZ_SYS_HOME=%TZ_SYS_HOME

VERBOSE=1 make %{?jobs:-j%jobs}

%install
%make_install
mkdir -p %{buildroot}/usr/share/privilege-control/

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/smack-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
mkdir -p %{buildroot}%{TZ_SYS_DB}

sed -i 's|TZ_SYS_DB|%{TZ_SYS_DB}|g' %{SOURCE1001}

%post
/sbin/ldconfig

/usr/share/privilege-control/db/updater.sh
chsmack -a 'System' %{TZ_SYS_DB}/.rules-db.db3*

%postun -p /sbin/ldconfig

api_feature_loader --verbose --dir=/usr/share/privilege-control/

%check
./db/updater.sh --check-files %{buildroot}

%files
%manifest %{name}.manifest
%license LICENSE
%{_libdir}/*.so.*
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
/etc/opt/upgrade/220.libprivilege-updater.patch.sh
%attr(755, root, root) %dir %{TZ_SYS_DB}

%files conf
%manifest %{name}.manifest
%{TZ_SYS_DB}/.privilege_control*.db

%files devel
%manifest %{name}.manifest
%{_includedir}/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
