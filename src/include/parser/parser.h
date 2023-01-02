/*-------------------------------------------------------------------------
 *
 * parser.h
 *		Definitions for the "raw" parser (flex and bison phases only)
 *
 * This is the external API for the raw lexing/parsing functions.
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/parser.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PARSER_H
#define PARSER_H

#include "nodes/parsenodes.h"


/*
 * RawParseMode determines the form of the string that raw_parser() accepts:
 *
 * RAW_PARSE_DEFAULT: parse a semicolon-separated list of SQL commands,
 * and return a List of RawStmt nodes.
 *
 * RAW_PARSE_TYPE_NAME: parse a type name, and return a one-element List
 * containing a TypeName node.
 *
 * RAW_PARSE_PLPGSQL_EXPR: parse a PL/pgSQL expression, and return
 * a one-element List containing a RawStmt node.
 *
 * RAW_PARSE_PLPGSQL_ASSIGNn: parse a PL/pgSQL assignment statement,
 * and return a one-element List containing a RawStmt node.  "n"
 * gives the number of dotted names comprising the target ColumnRef.
 */
typedef enum
{
	RAW_PARSE_DEFAULT = 0,
	RAW_PARSE_TYPE_NAME,
	RAW_PARSE_PLPGSQL_EXPR,
	RAW_PARSE_PLPGSQL_ASSIGN1,
	RAW_PARSE_PLPGSQL_ASSIGN2,
	RAW_PARSE_PLPGSQL_ASSIGN3
} RawParseMode;

/* Values for the backslash_quote GUC */
typedef enum
{
	BACKSLASH_QUOTE_OFF,
	BACKSLASH_QUOTE_ON,
	BACKSLASH_QUOTE_SAFE_ENCODING
}			BackslashQuoteType;

typedef enum
{
	SQL_DIALECT_PG,
	SQL_DIALECT_TSQL
} SQLDialect;

typedef enum
{
	DATEFIRST_MONDAY,
	DATEFIRST_TUESDAY,
	DATEFIRST_WEDNESDAY,
	DATEFIRST_THURSDAY,
	DATEFIRST_FRIDAY,
	DATEFIRST_SATURDAY,
	DATEFIRST_SUNDAY
} DATEFIRST;

/* GUC variables in scan.l (every one of these is a bad idea :-() */
extern PGDLLIMPORT int backslash_quote;
extern PGDLLIMPORT bool escape_string_warning;
extern PGDLLIMPORT bool standard_conforming_strings;
extern PGDLLEXPORT int sql_dialect;
extern PGDLLEXPORT bool pltsql_case_insensitive_identifiers;

extern PGDLLEXPORT char* pltsql_server_collation_name;

/* Primary entry point for the raw parsing functions */
extern List *raw_parser(const char *str, RawParseMode mode);

/* Utility functions exported by gram.y (perhaps these should be elsewhere) */
extern List *SystemFuncName(char *name);
extern TypeName *SystemTypeName(char *name);


/* Hook to extend backend parser */
typedef List * (*raw_parser_hook_type) (const char *str, RawParseMode mode);
extern PGDLLEXPORT raw_parser_hook_type raw_parser_hook;

/* Hooks needed in grammar rule in gram.y */
typedef List * (*rewrite_typmod_expr_hook_type) (List *expr_list);
extern PGDLLEXPORT rewrite_typmod_expr_hook_type rewrite_typmod_expr_hook;

typedef void (*validate_numeric_typmods_hook_type) (List **typmods, bool isNumeric, void* yyscanner);
extern PGDLLEXPORT validate_numeric_typmods_hook_type validate_numeric_typmods_hook;

typedef bool (*check_recursive_cte_hook_type) (WithClause *with_clause);
extern PGDLLEXPORT check_recursive_cte_hook_type check_recursive_cte_hook;

typedef void (*fix_domain_typmods_hook_type) (TypeName *typname);
extern PGDLLEXPORT fix_domain_typmods_hook_type fix_domain_typmods_hook;

#define TSQLMaxTypmod -8000
#define TSQLMaxNumPrecision 38
#define TSQLHexConstTypmod -16
#endif							/* PARSER_H */
