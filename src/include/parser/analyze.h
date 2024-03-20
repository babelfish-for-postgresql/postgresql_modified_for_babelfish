/*-------------------------------------------------------------------------
 *
 * analyze.h
 *		parse analysis for optimizable statements
 *
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/analyze.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ANALYZE_H
#define ANALYZE_H

#include "nodes/params.h"
#include "nodes/queryjumble.h"
#include "parser/parse_node.h"

/* Hook for plugins to get control at end of parse analysis */
typedef void (*post_parse_analyze_hook_type) (ParseState *pstate,
											  Query *query,
											  JumbleState *jstate);
extern PGDLLEXPORT post_parse_analyze_hook_type post_parse_analyze_hook;

/* Hook for plugins to get control with the raw parse tree */
typedef void (*pre_parse_analyze_hook_type) (ParseState *pstate, RawStmt *parseTree);

extern PGDLLEXPORT pre_parse_analyze_hook_type pre_parse_analyze_hook;

/* Hook to handle qualifiers in returning list for output clause */
typedef void (*pre_transform_returning_hook_type) (Query *query, List *returningList, ParseState *pstate);
extern PGDLLEXPORT pre_transform_returning_hook_type pre_transform_returning_hook;

typedef void (*post_transform_delete_hook_type) (ParseState *pstate, DeleteStmt *stmt, Query *query);
extern PGDLLEXPORT post_transform_delete_hook_type post_transform_delete_hook;

/* Hook to modify insert statement in output clause */
typedef void (*pre_transform_insert_hook_type) (ParseState *pstate, InsertStmt *stmt, Query *query);
extern PGDLLEXPORT pre_transform_insert_hook_type pre_transform_insert_hook;

/* Hook to perform self-join transformation on UpdateStmt in output clause */
typedef Node* (*pre_output_clause_transformation_hook_type) (ParseState *pstate, UpdateStmt *stmt, Query *query);
extern PGDLLEXPORT pre_output_clause_transformation_hook_type pre_output_clause_transformation_hook;

/* Hook to read a global variable with info on output clause */
typedef bool (*get_output_clause_status_hook_type) (void);
extern PGDLLEXPORT get_output_clause_status_hook_type get_output_clause_status_hook;

/* Hook for plugins to get control after an insert row transform */
typedef void (*post_transform_insert_row_hook_type) (List *icolumns, List *exprList, Oid relid);
extern PGDLLEXPORT post_transform_insert_row_hook_type post_transform_insert_row_hook;

/* Hook for handle target table before transforming from clause */
typedef int (*set_target_table_alternative_hook_type) (ParseState *pstate, Node *stmt, CmdType command);
extern PGDLLEXPORT set_target_table_alternative_hook_type set_target_table_alternative_hook;

/* Hook for handle target table before transforming from clause */
typedef void (*pre_transform_setop_tree_hook_type) (SelectStmt *stmt, SelectStmt *leftmostSelect);
extern PGDLLEXPORT pre_transform_setop_tree_hook_type pre_transform_setop_tree_hook;

/* Hook for handle target table before transforming from clause */
typedef void (*pre_transform_setop_sort_clause_hook_type) (ParseState *pstate, Query *qry, List *sortClause, Query *leftmostQuery);
extern PGDLLEXPORT pre_transform_setop_sort_clause_hook_type pre_transform_setop_sort_clause_hook;

/* Hook for transform pivot clause in tsql select stmt */
typedef void (*transform_pivot_clause_hook_type)(ParseState *pstate, SelectStmt *stmt);
extern PGDLLEXPORT transform_pivot_clause_hook_type transform_pivot_clause_hook;

extern Query *parse_analyze_fixedparams(RawStmt *parseTree, const char *sourceText,
										const Oid *paramTypes, int numParams, QueryEnvironment *queryEnv);
extern Query *parse_analyze(RawStmt *parseTree, const char *sourceText,
							Oid *paramTypes, int numParams, QueryEnvironment *queryEnv);
extern Query *parse_analyze_varparams(RawStmt *parseTree, const char *sourceText,
									  Oid **paramTypes, int *numParams, QueryEnvironment *queryEnv);
extern Query *parse_analyze_withcb(RawStmt *parseTree, const char *sourceText,
								   ParserSetupHook parserSetup,
								   void *parserSetupArg,
								   QueryEnvironment *queryEnv);

extern Query *parse_sub_analyze(Node *parseTree, ParseState *parentParseState,
								CommonTableExpr *parentCTE,
								bool locked_from_parent,
								bool resolve_unknowns);

extern List *transformInsertRow(ParseState *pstate, List *exprlist,
								List *stmtcols, List *icolumns, List *attrnos,
								bool strip_indirection);
extern List *transformUpdateTargetList(ParseState *pstate,
									   List *origTlist);
extern Query *transformTopLevelStmt(ParseState *pstate, RawStmt *parseTree);
extern Query *transformStmt(ParseState *pstate, Node *parseTree);

extern bool stmt_requires_parse_analysis(RawStmt *parseTree);
extern bool analyze_requires_snapshot(RawStmt *parseTree);

extern const char *LCS_asString(LockClauseStrength strength);
extern void CheckSelectLocking(Query *qry, LockClauseStrength strength);
extern void applyLockingClause(Query *qry, Index rtindex,
							   LockClauseStrength strength,
							   LockWaitPolicy waitPolicy, bool pushedDown);

extern List *BuildOnConflictExcludedTargetlist(Relation targetrel,
											   Index exclRelIndex);

extern SortGroupClause *makeSortGroupClauseForSetOp(Oid rescoltype, bool require_hash);

#endif							/* ANALYZE_H */
