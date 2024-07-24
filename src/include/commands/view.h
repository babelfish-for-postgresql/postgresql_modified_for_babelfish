/*-------------------------------------------------------------------------
 *
 * view.h
 *
 *
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/view.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef VIEW_H
#define VIEW_H

#include "catalog/objectaddress.h"
#include "nodes/parsenodes.h"

extern ObjectAddress DefineView(ViewStmt *stmt, const char *queryString,
								int stmt_location, int stmt_len);

extern void StoreViewQuery(Oid viewOid, Query *viewParse, bool replace);

typedef void (*store_view_definition_hook_type) (const char *queryString, ObjectAddress address);
extern PGDLLIMPORT store_view_definition_hook_type	store_view_definition_hook;

typedef void (*inherit_view_constraints_from_table_hook_type) (ColumnDef  *col, Oid tableOid, AttrNumber colId);
extern PGDLLEXPORT inherit_view_constraints_from_table_hook_type inherit_view_constraints_from_table_hook;

typedef Query *(*parse_analyze_babelfish_view_hook_type) (ViewStmt *stmt, RawStmt *rawstmt, const char *queryString);
extern PGDLLEXPORT parse_analyze_babelfish_view_hook_type parse_analyze_babelfish_view_hook;
#endif							/* VIEW_H */
