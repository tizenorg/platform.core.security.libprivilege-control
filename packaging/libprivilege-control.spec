#%define udev_libdir /usr/lib/udev

Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.26.TIZEN
Release:    1
Group:      System/Security
License:    Apache 2.0
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
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

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
cp %{SOURCE1001} .

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

install -D -d %{buildroot}/etc/rc.d/rc3.d/
install -D -d %{buildroot}/etc/rc.d/rc4.d/
ln -sf ../init.d/smack_default_labeling %{buildroot}/etc/rc.d/rc3.d/S45smack_default_labeling
ln -sf ../init.d/smack_default_labeling %{buildroot}/etc/rc.d/rc4.d/S45smack_default_labeling
ln -sf ../init.d/smack_rules %{buildroot}/etc/rc.d/rc3.d/S02smack_rules
ln -sf ../init.d/smack_rules %{buildroot}/etc/rc.d/rc4.d/S02smack_rules

mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
install -m 644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/
ln -s ../smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/basic.target.wants/

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

if [ ! -e "/usr/share/privilege-control" ]
then
        mkdir -p /usr/share/privilege-control/
fi


%files
%manifest %{name}.manifest
%{_libdir}/*.so.*
%{_bindir}/slp-su
%{_datarootdir}/privilege-control/*
#%{udev_libdir}/rules.d/*
#%attr(755,root,root) %{udev_libdir}/uname_env
%{_datadir}/license/%{name}

%files conf
%manifest %{name}.manifest
/etc/group
/etc/passwd
/opt/etc/smack/*
%attr(755,root,root) /etc/rc.d/*
/usr/lib/systemd/system/smack-default-labeling.service
/usr/lib/systemd/system/basic.target.wants/smack-default-labeling.service
/opt/dbspace/.privilege_control*.db

%files devel
%manifest %{name}.manifest
%{_includedir}/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
