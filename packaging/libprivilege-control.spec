#%define udev_libdir /usr/lib/udev

Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.38.TIZEN
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    %{name}-conf.manifest
Source2:    smack-default-labeling.service
BuildRequires: cmake
BuildRequires: libcap-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(libiri)
Requires: smack-privilege-config

%description
development package of library to control privilege of in-house application

%package devel
Summary:    Control privilege of application (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires:   pkgconfig(libsmack)

%description devel
Library to control privilege of application (devel)

%package conf
Summary:    Control privilege of application files
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires:   /usr/bin/chsmack

%description conf
Library to control privilege of application files


%prep
%setup -q

%build
export CFLAGS="${CFLAGS} -Wno-implicit-function-declaration"
%cmake . -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
%make_install

mkdir -p %{buildroot}/etc
mv %{buildroot}/opt/etc/passwd %{buildroot}/etc/passwd
mv %{buildroot}/opt/etc/group %{buildroot}/etc/group

cp -a %{SOURCE1} %{buildroot}%{_datadir}/
cp -a %{SOURCE2} %{buildroot}%{_datadir}/

mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
install -m 644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/
ln -s ../smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/basic.target.wants/

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/smack-late-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-late-rules.service
ln -sf /usr/lib/systemd/system/smack-early-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-early-rules.service

mkdir -p %{buildroot}/usr/lib/systemd/system/tizen-runtime.target.wants
ln -s /usr/lib/systemd/system/smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service

%post
if [ ! -e "/home/app" ]
then
        mkdir -p /home/app
fi

if [ ! -e "/home/developer" ]
then
        mkdir -p /home/developer
fi

chown 5000:5000 /home/app
chmod 755 /home/app
chown 5100:5100 /home/developer
chmod 755 /home/developer


if [ ! -e "/opt/etc/smack-app/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app/accesses.d
fi

if [ ! -e "/opt/etc/smack-app-early/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app-early/accesses.d
fi

%files
%{_libdir}/*.so.*
%{_bindir}/slp-su
#%{udev_libdir}/rules.d/*
#%attr(755,root,root) %{udev_libdir}/uname_env
%{_datadir}/license/%{name}
#systemd service
/usr/lib/systemd/system/smack-late-rules.service
/usr/lib/systemd/system/smack-early-rules.service
/usr/bin/rule_loader
#link to activate systemd service
/usr/lib/systemd/system/multi-user.target.wants/smack-late-rules.service
/usr/lib/systemd/system/multi-user.target.wants/smack-early-rules.service

%files conf
/etc/group
/etc/passwd
%attr(755,root,root) /etc/rc.d/*
/usr/share/smack-default-labeling.service
/usr/lib/systemd/system/smack-default-labeling.service
/usr/lib/systemd/system/basic.target.wants/smack-default-labeling.service
/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service
%manifest %{_datadir}/%{name}-conf.manifest
/opt/dbspace/.privilege_control*.db

%files devel
%{_includedir}/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
