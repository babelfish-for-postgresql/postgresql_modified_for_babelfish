/*-------------------------------------------------------------------------
 *
 * Utility routines for babelfish objects
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/bin/pg_dump/dumpall_babel_utils.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef DUMPALL_BABEL_UTILS_H
#define DUMPALL_BABEL_UTILS_H

#include "pqexpbuffer.h"

extern char *bbf_db_name;

extern void getBabelfishRolesQuery(PQExpBuffer buf, char *role_catalog, bool drop_query);
extern void getBabelfishRoleMembershipQuery(PQExpBuffer buf, char *role_catalog);

#endif
