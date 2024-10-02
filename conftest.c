/* confdefs.h */
#define PACKAGE_NAME "PostgreSQL"
#define PACKAGE_TARNAME "postgresql"
#define PACKAGE_VERSION "16.4"
#define PACKAGE_STRING "PostgreSQL 16.4"
#define PACKAGE_BUGREPORT "pgsql-bugs@lists.postgresql.org"
#define PACKAGE_URL "https://www.postgresql.org/"
#define CONFIGURE_ARGS " '--prefix=/local/home/changti/postgres/' '--without-readline' '--without-zlib' '--enable-debug' '--enable-cassert' 'CFLAGS=-ggdb' '--with-libxml' '--with-uuid=ossp' '--with-icu'"
#define PG_MAJORVERSION "16"
#define PG_MAJORVERSION_NUM 16
#define PG_MINORVERSION_NUM 4
#define PG_VERSION "16.4"
#define DEF_PGPORT 5432
#define DEF_PGPORT_STR "5432"
#define BLCKSZ 8192
#define RELSEG_SIZE 131072
#define XLOG_BLCKSZ 8192
#define HAVE_VISIBILITY_ATTRIBUTE 1
#define DLSUFFIX ".so"
#define USE_ASSERT_CHECKING 1
#define ENABLE_THREAD_SAFETY 1
#define USE_ICU 1
#define PG_KRB_SRVNAM "postgres"
#define HAVE_UUID_OSSP 1
#define USE_LIBXML 1
#define STDC_HEADERS 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
/* end confdefs.h.  */
#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_STRING_H
# if !defined STDC_HEADERS && defined HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <memory.h>
