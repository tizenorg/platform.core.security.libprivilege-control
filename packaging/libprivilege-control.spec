Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.6
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
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

%description conf
Library to control privilege of application files


%prep
%setup -q

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install


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
/usr/lib/*.so.*
/usr/bin/slp-su
/usr/share/privilege-control/*
/lib/udev/rules.d/*

%files conf
/opt/etc/group
/opt/etc/passwd

%files devel
/usr/include/*.h
/usr/lib/*.so
/usr/lib/pkgconfig/*.pc
