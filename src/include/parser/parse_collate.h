/*-------------------------------------------------------------------------
 *
 * parse_collate.h
 *	Routines for assigning collation information.
 *
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/parse_collate.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PARSE_COLLATE_H
#define PARSE_COLLATE_H

#include "parser/parse_node.h"

extern void assign_query_collations(ParseState *pstate, Query *query);

extern void assign_list_collations(ParseState *pstate, List *exprs);

extern void assign_expr_collations(ParseState *pstate, Node *expr);

extern Oid	select_common_collation(ParseState *pstate, List *exprs, bool none_ok);

typedef bool (*avoid_collation_override_hook_type)(Oid funcid);
extern PGDLLEXPORT avoid_collation_override_hook_type avoid_collation_override_hook;

#endif							/* PARSE_COLLATE_H */
