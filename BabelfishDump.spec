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
%define _buildid .1

%undefine _missing_build_ids_terminate_build

Name: BabelfishDump
Summary: Postgresql dump utilities modified for Babelfish
Version: 17.7
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

# Update bug report and package links
sed -i 's|PACKAGE_BUGREPORT|"https://github.com/babelfish-for-postgresql/babelfish_extensions/issues"|g' src/bin/pg_dump/pg_dump.c
sed -i 's|PACKAGE_BUGREPORT|"https://github.com/babelfish-for-postgresql/babelfish_extensions/issues"|g' src/bin/pg_dump/pg_dumpall.c
sed -i 's|PACKAGE_NAME|"Babelfish"|g' src/bin/pg_dump/pg_dump.c
sed -i 's|PACKAGE_NAME|"Babelfish"|g' src/bin/pg_dump/pg_dumpall.c
sed -i 's|PACKAGE_URL|"https://github.com/babelfish-for-postgresql/babelfish-for-postgresql/wiki"|g' src/bin/pg_dump/pg_dump.c
sed -i 's|PACKAGE_URL|"https://github.com/babelfish-for-postgresql/babelfish-for-postgresql/wiki"|g' src/bin/pg_dump/pg_dumpall.c

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
* Fri July 25 2025 Tanya Gupta <tanyagp@amazon.com> - 17.7-1
- Dump Babelfish operator classes for numeric-fixeddecimal comparisons to support index scan

* Fri May 16 2025 Sumit Jaiswal <sumiji@amazon.com> - 17.7-1
- Dump Babelfish operator classes for numeric-int comparisons to support index scan

* Wed Dec 11 2024 Sharu Goel <goelshar@amazon.com> - 17.5-1
- Add support to dump linked roles associated with members of db_owner role

* Wed Dec 11 2024 ANJU BHARTI <abanju@amazon.com> - 17.5-1
- Handle dump logic for babelfish db_ddladmin fixed database role

* Wed Dec 11 2024 Harsh Lunagariya <lunharsh@amazon.com> - 17.5-1
- Handle dump logic for babelfish db_securityadmin fixed database role

* Wed Dec 11 2024 ANJU BHARTI <abanju@amazon.com> - 17.5-1
- Handle dump logic for babelfish db_creator fixed server role

* Wed Dec 11 2024 Shalini Lohia <lshalini@amazon.com> - 17.5-1
- Handle dump logic for babelfish db_datareader/db_datawriter fixed database roles

* Wed Dec 11 2024 Tanzeel Khan <tzlkhan@amazon.com> - 17.5-1
- Handle dump logic for babelfish db_accessadmin fixed database role

* Wed Dec 11 2024 ANJU BHARTI <abanju@amazon.com> - 17.5-1
- Handle dump logic for babelfish securityadmin fixed server role

* Tue Nov 19 2024 Rishabh Tanwar <ritanwar@amazon.com> - 17.5-1
- Enable babelfishpg_tsql.dump_restore GUC while restoring roles

* Thu Oct 3 2024 Tanzeel Khan <tzlkhan@amazon.com> - 17.5-1
- Dump physical database aclprivs for fixed database roles

* Mon Aug 5 2024 Masahiko Sawada <msawada@postgresql.com> - 16.4-1
- [CVE-2024-7348] Restrict accesses to non-system views and foreign tables during pg_dump.

* Mon Jul 8 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.4-1
- Include ordering for constraints on babelfish tables

* Fri Jun 21 2024 Sumit Jaiswal <sumiji@amazon.com> - 16.4-1
- Support dump/restore of Partition Function and Partition Scheme catalogs

* Mon Jun 17 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.3-2
- Improve catalog handling in bbf_dump

* Mon May 20 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.3-1
- Update bug report and documentation links for BabelfishDump

* Tue Apr 02 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.3-1
- Do not dump babelfish_domain_mapping catalog table for database-level dump

* Fri Mar 22 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.3-1
- Support Babelfish schema-only and data-only dump/restore

* Tue Mar 05 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.3-1
- Correctly dump the data of babelfish_extended_properties

* Tue Jan 16 2024 Rishabh Tanwar <ritanwar@amazon.com> - 16.1-2
- Updated BabelfishDump RPM version to 16.1

* Fri Dec 29 2023 Rishabh Tanwar <ritanwar@amazon.com> - 16.1-2
- Skip dumping GRANTs between default Babelfish roles.
- Handle dump logic for new bbf_role_admin role
