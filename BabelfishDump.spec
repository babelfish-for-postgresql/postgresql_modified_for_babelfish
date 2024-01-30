# This spec file and ancillary files are licensed in accordance with
# The PostgreSQL license.
# This spec file bundles the Babelfish dump utilities (bbf_dump/bbf_dumpall)
# into an RPM.

# In this file you can find the default build package list macros.
# These can be overridden by defining on the rpm command line:
# rpm --define 'packagename 1' .... to force the package to build.
# rpm --define 'packagename 0' .... to force the package NOT to build.

%{!?external_libpq:%global external_libpq 0}
%{!?ssl:%global ssl 1}
%{!?icu:%global icu 1}
%{!?kerberos:%global kerberos 1}
%{!?uuid:%global uuid 1}
%{!?xml:%global xml 1}
%{!?pam:%global pam 1}

# https://fedoraproject.org/wiki/Packaging:Guidelines#Packaging_of_Additional_RPM_Macros
%global macrosdir %(d=%{_rpmconfigdir}/macros.d; [ -d $d ] || d=%{_sysconfdir}/rpm; echo $d)

%define _trivial .0
%define _buildid .2

%undefine _missing_build_ids_terminate_build

Name: BabelfishDump
Summary: Postgresql dump utilities modified for Babelfish
Version: 16.1
Release: 1%{?dist}%{?_trivial}%{?_buildid}
License: PostgreSQL
Url: https://github.com/babelfish-for-postgresql/postgresql_modified_for_babelfish

BuildRequires: make
BuildRequires: lz4-devel
BuildRequires: gcc perl
BuildRequires: glibc-devel bison flex
BuildRequires: readline-devel zlib-devel
%if %external_libpq
BuildRequires: libpq-devel >= %version
%endif

%if %ssl
BuildRequires: openssl-devel
%endif

%if %kerberos
BuildRequires: krb5-devel
%endif

%if %uuid
BuildRequires: uuid-devel
%endif

%if %xml
BuildRequires: libxml2-devel
%endif

%if %icu
BuildRequires:	libicu-devel
%endif

%if %pam
BuildRequires: pam-devel
%endif

Source: %{name}.tar.gz

# https://bugzilla.redhat.com/1464368
# and do not provide pkgconfig RPM provides (RHBZ#1980992) and #2121696
%global __provides_exclude_from %{_libdir}/(pgsql|pkgconfig)

%description
This package provides utilities to dump a Babelfish database.

%prep
%setup -q -n %{name}

# Change binary names
sed -i "s/pg_dump/bbf_dump/g" src/bin/pg_dump/pg_dumpall.c
sed -i "s/pg_dump (PostgreSQL)/bbf_dump (pg_dump compatible with Babelfish for PostgreSQL)/g" src/bin/pg_dump/pg_dump.c
sed -i "s/bbf_dump (PostgreSQL)/bbf_dump (pg_dump compatible with Babelfish for PostgreSQL)/g" src/bin/pg_dump/pg_dumpall.c
sed -i "s/bbf_dumpall (PostgreSQL)/bbf_dumpall (pg_dumpall compatible with Babelfish for PostgreSQL)/g" src/bin/pg_dump/pg_dumpall.c

%build
# Building BabelfishDump

# Fiddling with CFLAGS.
CFLAGS="${CFLAGS:-%optflags}"

# Strip out -ffast-math from CFLAGS....
CFLAGS=`echo $CFLAGS|xargs -n 1|grep -v ffast-math|xargs -n 100`
export CFLAGS

common_configure_options='
	--disable-rpath
%if %ssl
	--with-openssl
%endif
%if %xml
	--with-libxml
%endif
%if %kerberos
	--with-gssapi
%endif
%if %uuid
	--with-ossp-uuid
%endif
%if %icu
	--with-icu
%endif
%if %pam
	--with-pam
%endif
	--with-lz4
	--with-readline
'

%configure $common_configure_options

make -C src/backend generated-headers
export NO_GENERATED_HEADERS=1
make -C src/bin/pg_dump pg_dump pg_dumpall

%install
make -C src/bin/pg_dump install DESTDIR=$RPM_BUILD_ROOT

# We don't need pg_restore
rm -f $RPM_BUILD_ROOT/usr/bin/pg_restore
# Rename binaries to bbf_* equivalent
mv $RPM_BUILD_ROOT/usr/bin/pg_dump $RPM_BUILD_ROOT/usr/bin/bbf_dump
mv $RPM_BUILD_ROOT/usr/bin/pg_dumpall $RPM_BUILD_ROOT/usr/bin/bbf_dumpall

%check
LD_LIBRARY_PATH=%{_builddir}/%{name}/src/interfaces/libpq $RPM_BUILD_ROOT/usr/bin/bbf_dumpall -V
LD_LIBRARY_PATH=%{_builddir}/%{name}/src/interfaces/libpq $RPM_BUILD_ROOT/usr/bin/bbf_dump -V

# FILES sections.
%files
%doc COPYRIGHT
%doc LICENSE.PostgreSQL
%{_bindir}/bbf_dump
%{_bindir}/bbf_dumpall

%changelog
* Tue Jan 16 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.1-2
- Updated BabelfishDump RPM version to 16.1

* Fri Dec 29 2023 Rishabh Tanwar <ritanwar@amazon.com> - 16.1-2
- Skip dumping GRANTs between default Babelfish roles.
- Handle dump logic for new bbf_role_admin role
