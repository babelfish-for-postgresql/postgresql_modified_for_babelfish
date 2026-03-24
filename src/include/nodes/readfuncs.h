/*-------------------------------------------------------------------------
 *
 * readfuncs.h
 *	  header file for read.c and readfuncs.c. These functions are internal
 *	  to the stringToNode interface and should not be used by anyone else.
 *
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/nodes/readfuncs.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef READFUNCS_H
#define READFUNCS_H

#include "nodes/nodes.h"

/*
 * variable in read.c that needs to be accessible to readfuncs.c
 */
#ifdef WRITE_READ_PARSE_PLAN_TREES
extern PGDLLIMPORT bool restore_location_fields;
#endif

/*
 * prototypes for functions in read.c (the lisp token parser)
 */
extern const char *pg_strtok(int *length);
extern char *debackslash(const char *token, int length);
extern void *nodeRead(const char *token, int tok_len);

/*
 * prototypes for functions in readfuncs.c
 */
extern Node *parseNodeString(void);

/*
 * Hook for extensions to handle custom node types in outNode/parseNodeString.
 * Same pattern as planner_hook, ProcessUtility_hook, etc.
 */
typedef void (*outNode_hook_type)(StringInfo str, const void *obj);
extern PGDLLIMPORT outNode_hook_type outNode_hook;

typedef Node *(*parseNodeString_hook_type)(const char *token, int length);
extern PGDLLIMPORT parseNodeString_hook_type parseNodeString_hook;

#endif							/* READFUNCS_H */
