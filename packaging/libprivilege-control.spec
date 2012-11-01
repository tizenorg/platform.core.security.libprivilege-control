%define udev_libdir /usr/lib/udev

Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.13
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    %{name}-conf.manifest
BuildRequires: cmake
BuildRequires: pkgconfig(libsmack)

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

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
%make_install
cp -a %{SOURCE1} %{buildroot}%{_datadir}/
install -D -d %{buildroot}/etc/rc.d/rc3.d/
install -D -d %{buildroot}/etc/rc.d/rc4.d/
ln -sf ../init.d/smack_default_labeling %{buildroot}/etc/rc.d/rc3.d/S45smack_default_labeling
ln -sf ../init.d/smack_default_labeling %{buildroot}/etc/rc.d/rc4.d/S45smack_default_labeling

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

%post conf
if [ -e "/etc/passwd" ]
then
        rm -f /etc/passwd
fi
ln -sf /opt/etc/passwd /etc/passwd

if [ -e "/etc/group" ]
then
        rm -f /etc/group
fi
ln -sf /opt/etc/group /etc/group


%files
%{_libdir}/*.so.*
%{_bindir}/slp-su
%{_datarootdir}/privilege-control/*
%{udev_libdir}/rules.d/*
%{_datadir}/license/%{name}

%files conf
/opt/etc/group
/opt/etc/passwd
/opt/etc/smack/*
%attr(755,root,root) /etc/rc.d/*
%manifest %{_datadir}/%{name}-conf.manifest

%files devel
%{_includedir}/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
