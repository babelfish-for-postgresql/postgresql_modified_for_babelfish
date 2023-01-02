/*-------------------------------------------------------------------------
 *
 * view.h
 *
 *
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
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
extern PGDLLEXPORT store_view_definition_hook_type	store_view_definition_hook;

typedef void (*inherit_view_constraints_from_table_hook_type) (ColumnDef  *col, Oid tableOid, AttrNumber colId);
extern PGDLLEXPORT inherit_view_constraints_from_table_hook_type inherit_view_constraints_from_table_hook;
#endif							/* VIEW_H */
