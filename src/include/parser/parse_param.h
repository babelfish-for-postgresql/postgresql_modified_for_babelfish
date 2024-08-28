/*-------------------------------------------------------------------------
 *
 * parse_param.h
 *	  handle parameters in parser
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/parse_param.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PARSE_PARAM_H
#define PARSE_PARAM_H

#include "parser/parse_node.h"

extern void setup_parse_fixed_parameters(ParseState *pstate,
										 const Oid *paramTypes, int numParams);
extern void setup_parse_variable_parameters(ParseState *pstate,
											Oid **paramTypes, int *numParams);
extern void check_variable_parameters(ParseState *pstate, Query *query);
extern bool query_contains_extern_params(Query *query);

/* Special hook to handle collation of param in Babelfish context */
typedef Oid (*handle_param_collation_hook_type) (Param *param);
extern PGDLLEXPORT handle_param_collation_hook_type handle_param_collation_hook;

#endif							/* PARSE_PARAM_H */
