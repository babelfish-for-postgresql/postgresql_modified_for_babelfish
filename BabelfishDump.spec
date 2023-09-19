# This spec file and ancillary files are licensed in accordance with

# The PostgreSQL license.


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

# https://fedoraproject.org/wiki/Packaging:Guidelines#Packaging_of_Additional_RPM_Macros

%global macrosdir %(d=%{_rpmconfigdir}/macros.d; [ -d $d ] || d=%{_sysconfdir}/rpm; echo $d)

%undefine _missing_build_ids_terminate_build

Summary: Postgresql dump utilities modified for Babelfish

Name: BabelfishDump

%global majorversion 15

Version: %{majorversion}.3

Release: 2%{?dist}

License: PostgreSQL
	
Url: https://github.com/babelfish-for-postgresql/postgresql_modified_for_babelfish

BuildArch: noarch


BuildRequires: make

BuildRequires: gcc

#BuildRequires: perl(ExtUtils::MakeMaker) glibc-devel bison flex gawk
	
BuildRequires: readline-devel zlib-devel

%if %external_libpq

BuildRequires: libpq-devel >= %version

%endif

# postgresql-setup build requires

BuildRequires: m4


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


Source: %{name}.tar.gz

# https://bugzilla.redhat.com/1464368

# and do not provide pkgconfig RPM provides (RHBZ#1980992) and #2121696

%global __provides_exclude_from %{_libdir}/(pgsql|pkgconfig)


%description

This package provides utilities to dump a Babelfish database.


Requires(post): glibc

Requires(postun): glibc


%prep

%setup -q -n %{name}

# Update binary versions
sed -i "s/pg_dump (PostgreSQL)/bbf_dump (pg_dump compatible with Babelfish for PostgreSQL)/g" src/bin/pg_dump/pg_dump.c
sed -i "s/pg_dumpall (PostgreSQL)/bbf_dumpall (pg_dumpall compatible with Babelfish for PostgreSQL)/g" src/bin/pg_dump/pg_dumpall.c

%build

# Building BabelfishDump

# Fiddling with CFLAGS.


CFLAGS="${CFLAGS:-%optflags}"

# Strip out -ffast-math from CFLAGS....

CFLAGS=`echo $CFLAGS|xargs -n 1|grep -v ffast-math|xargs -n 100`

export CFLAGS


common_configure_options='

	--disable-rpath

	--enable-debug

	--enable-cassert

%if %ssl
	
	--with-openssl

	--with-ssl=libssl3
	
%endif

	--with-zlib

	--with-libxml

	--with-readline

%if %kerberos

	--with-gssapi

%endif

%if %uuid

	--with-ossp-uuid

%endif

%if %icu

	--with-icu

%endif
'

export LIBS="-lz -lc -lssl -lcrypto -lkrb5 -lcom_err -lgssapi_krb5 -lk5crypto -ldl -lkrb5support -lssl3"

%configure $common_configure_options

make -C src/backend generated-headers
make -C src/bin/pg_dump -j4 pg_dump pg_dumpall


%install

make -C src/bin/pg_dump install DESTDIR=$RPM_BUILD_ROOT

# We don't need pg_restore
rm -f $RPM_BUILD_ROOT/usr/bin/pg_restore

# Rename binaries to bbf_* equivalent
mv $RPM_BUILD_ROOT/usr/bin/pg_dump $RPM_BUILD_ROOT/usr/bin/bbf_dump
mv $RPM_BUILD_ROOT/usr/bin/pg_dumpall $RPM_BUILD_ROOT/usr/bin/bbf_dumpall

%check
$RPM_BUILD_ROOT/usr/bin/bbf_dumpall -V
$RPM_BUILD_ROOT/usr/bin/bbf_dump -V

# FILES sections.
%files

%{_bindir}/bbf_dump

%{_bindir}/bbf_dumpall

%changelog
