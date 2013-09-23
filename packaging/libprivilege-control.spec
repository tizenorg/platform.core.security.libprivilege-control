Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.42.TIZEN
Release:    1
Group:      Security/Access Control
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source2:    smack-default-labeling.service
Source1001:    %{name}.manifest
BuildRequires: cmake
BuildRequires: libcap-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(libiri)
BuildRequires: pkgconfig(sqlite3)
Requires:   smack-privilege-config
Requires:   sqlite

%description
development package of library to control privilege of in-house application

%package devel
Summary:    Control privilege of application (devel)
Requires:   %{name} = %{version}-%{release}
Requires:   pkgconfig(libsmack)

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
%cmake . -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
         -DCMAKE_VERBOSE_MAKEFILE=ON

VERBOSE=1 make %{?jobs:-j%jobs}

%install
%make_install


mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
install -m 644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/
ln -s ../smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/basic.target.wants/


mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/smack-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service

mkdir -p %{buildroot}/usr/lib/systemd/system/tizen-runtime.target.wants
ln -s /usr/lib/systemd/system/smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


if [ ! -e "/opt/etc/smack-app/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app/accesses.d
fi

if [ ! -e "/opt/etc/smack-app-early/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app-early/accesses.d
fi

sqlite3 /opt/dbspace/.rules-db.db3 < /opt/dbspace/rules-db.sql
rm -f /opt/dbspace/rules-db.sql

sqlite3 /opt/dbspace/.rules-db.db3 < /opt/dbspace/rules-db-data.sql
rm -f /opt/dbspace/rules-db-data.sql

api_feature_loader --verbose

%files
%manifest %{name}.manifest
%license LICENSE
%{_libdir}/*.so.*
%{_libdir}/librules-db-sql-udf.so
%{_bindir}/slp-su


%files conf
%manifest %{name}.manifest

/usr/lib/systemd/system/smack-rules.service
/usr/bin/api_feature_loader
#link to activate systemd service
/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
/opt/dbspace/rules-db.sql
/opt/dbspace/rules-db-data.sql
/opt/etc/smack/load-rules-db.sql

#/usr/share/smack-default-labeling.service
/usr/lib/systemd/system/smack-default-labeling.service
/usr/lib/systemd/system/basic.target.wants/smack-default-labeling.service
/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service
/opt/dbspace/.privilege_control*.db

%files devel
%manifest %{name}.manifest
%{_includedir}/*.h
%{_libdir}/libprivilege-control.so
%{_libdir}/pkgconfig/*.pc
