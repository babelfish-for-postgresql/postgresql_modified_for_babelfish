/*-------------------------------------------------------------------------
 *
 * analyze.h
 *		parse analysis for optimizable statements
 *
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/analyze.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ANALYZE_H
#define ANALYZE_H

#include "parser/parse_node.h"

/* Hook for plugins to get control at end of parse analysis */
typedef void (*post_parse_analyze_hook_type) (ParseState *pstate,
											  Query *query);
extern PGDLLIMPORT post_parse_analyze_hook_type post_parse_analyze_hook;

/* Hook for plugins to get control with the raw parse tree */
typedef void (*pre_parse_analyze_hook_type) (ParseState *pstate, RawStmt *parseTree);

extern PGDLLIMPORT pre_parse_analyze_hook_type pre_parse_analyze_hook;

/* Hook to handle qualifiers in returning list for output clause */
typedef void (*pre_transform_returning_hook_type) (CmdType command, 
										List *returningList, ParseState *pstate);

extern PGDLLIMPORT pre_transform_returning_hook_type pre_transform_returning_hook;

/* Hook to perform self-join transformation on UpdateStmt in output clause */
typedef Node* (*pre_output_clause_transformation_hook_type) (ParseState *pstate, UpdateStmt *stmt, CmdType command);
extern PGDLLIMPORT pre_output_clause_transformation_hook_type pre_output_clause_transformation_hook;

/* Hook to read a global variable with info on output clause */
typedef bool (*get_output_clause_status_hook_type) (void);
extern PGDLLIMPORT get_output_clause_status_hook_type get_output_clause_status_hook;

/* Hook for plugins to get control after an insert row transform */
typedef void (*post_transform_insert_row_hook_type) (List *icolumns, List *exprList, Oid relid);
extern PGDLLIMPORT post_transform_insert_row_hook_type post_transform_insert_row_hook;

extern Query *parse_analyze(RawStmt *parseTree, const char *sourceText,
							Oid *paramTypes, int numParams, QueryEnvironment *queryEnv);
extern Query *parse_analyze_varparams(RawStmt *parseTree, const char *sourceText,
									  Oid **paramTypes, int *numParams);

extern Query *parse_sub_analyze(Node *parseTree, ParseState *parentParseState,
								CommonTableExpr *parentCTE,
								bool locked_from_parent,
								bool resolve_unknowns);

extern Query *transformTopLevelStmt(ParseState *pstate, RawStmt *parseTree);
extern Query *transformStmt(ParseState *pstate, Node *parseTree);

extern bool analyze_requires_snapshot(RawStmt *parseTree);

extern const char *LCS_asString(LockClauseStrength strength);
extern void CheckSelectLocking(Query *qry, LockClauseStrength strength);
extern void applyLockingClause(Query *qry, Index rtindex,
							   LockClauseStrength strength,
							   LockWaitPolicy waitPolicy, bool pushedDown);

extern List *BuildOnConflictExcludedTargetlist(Relation targetrel,
											   Index exclRelIndex);

#endif							/* ANALYZE_H */
