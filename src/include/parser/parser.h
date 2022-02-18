/*-------------------------------------------------------------------------
 *
 * parser.h
 *		Definitions for the "raw" parser (flex and bison phases only)
 *
 * This is the external API for the raw lexing/parsing functions.
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/parser.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PARSER_H
#define PARSER_H

#include "nodes/parsenodes.h"


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
	TSQL_FORXML_RAW,
	TSQL_FORXML_AUTO,
	TSQL_FORXML_PATH,
	TSQL_FORXML_EXPLICIT
} TSQLFORXMLMode;

typedef enum
{
	TSQL_XML_DIRECTIVE_BINARY_BASE64,
	TSQL_XML_DIRECTIVE_TYPE
} TSQLXMLDirective;

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
extern int	backslash_quote;
extern bool escape_string_warning;
extern PGDLLIMPORT bool standard_conforming_strings;
extern int sql_dialect;
extern bool pltsql_case_insensitive_identifiers;

extern char* pltsql_server_collation_name;

/* Primary entry point for the raw parsing functions */
extern List *raw_parser(const char *str);

/* Utility functions exported by gram.y (perhaps these should be elsewhere) */
extern List *SystemFuncName(char *name);
extern TypeName *SystemTypeName(char *name);


/* Hook to extend backend parser */
typedef List * (*raw_parser_hook_type) (const char *str);
extern PGDLLIMPORT raw_parser_hook_type raw_parser_hook;

/* Hooks needed in grammar rule in gram.y */
typedef List * (*rewrite_typmod_expr_hook_type) (List *expr_list);
extern PGDLLIMPORT rewrite_typmod_expr_hook_type rewrite_typmod_expr_hook;

typedef void (*validate_numeric_typmods_hook_type) (List **typmods, bool isNumeric, void* yyscanner);
extern PGDLLIMPORT validate_numeric_typmods_hook_type validate_numeric_typmods_hook;

typedef bool (*check_recursive_cte_hook_type) (WithClause *with_clause);
extern PGDLLIMPORT check_recursive_cte_hook_type check_recursive_cte_hook;

#define TSQLMaxTypmod -8000
#define TSQLMaxNumPrecision 38
#define TSQLHexConstTypmod -16
#endif							/* PARSER_H */
