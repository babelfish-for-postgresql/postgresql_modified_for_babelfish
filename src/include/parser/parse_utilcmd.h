/*-------------------------------------------------------------------------
 *
 * parse_utilcmd.h
 *		parse analysis for utility commands
 *
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/parse_utilcmd.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PARSE_UTILCMD_H
#define PARSE_UTILCMD_H

#include "parser/parse_node.h"

struct AttrMap;					/* avoid including attmap.h here */


/* IDENTITY datatype hook */
typedef void (*pltsql_identity_datatype_hook_type) (ParseState *pstate,
													ColumnDef *column);
extern PGDLLEXPORT pltsql_identity_datatype_hook_type pltsql_identity_datatype_hook;
typedef void (*post_transform_column_definition_hook_type) (ParseState *pstate, RangeVar* relation, ColumnDef *column, List **alist);
typedef void (*post_transform_table_definition_hook_type) (ParseState *pstate, RangeVar* relation, char *relname, List **alist);
extern PGDLLEXPORT post_transform_column_definition_hook_type post_transform_column_definition_hook;
extern PGDLLEXPORT post_transform_table_definition_hook_type post_transform_table_definition_hook;

extern List *transformCreateStmt(CreateStmt *stmt, const char *queryString);
extern AlterTableStmt *transformAlterTableStmt(Oid relid, AlterTableStmt *stmt,
											   const char *queryString,
											   List **beforeStmts,
											   List **afterStmts);
extern IndexStmt *transformIndexStmt(Oid relid, IndexStmt *stmt,
									 const char *queryString);
extern CreateStatsStmt *transformStatsStmt(Oid relid, CreateStatsStmt *stmt,
										   const char *queryString);
extern void transformRuleStmt(RuleStmt *stmt, const char *queryString,
							  List **actions, Node **whereClause);
extern List *transformCreateSchemaStmtElements(List *schemaElts,
											   const char *schemaName);
extern PartitionBoundSpec *transformPartitionBound(ParseState *pstate, Relation parent,
												   PartitionBoundSpec *spec);
extern List *expandTableLikeClause(RangeVar *heapRel,
								   TableLikeClause *table_like_clause);
extern IndexStmt *generateClonedIndexStmt(RangeVar *heapRel,
										  Relation source_idx,
										  const struct AttrMap *attmap,
										  Oid *constraintOid);

#endif							/* PARSE_UTILCMD_H */
