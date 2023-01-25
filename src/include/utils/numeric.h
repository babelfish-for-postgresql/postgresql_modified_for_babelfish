/*-------------------------------------------------------------------------
 *
 * numeric.h
 *	  Definitions for the exact numeric data type of Postgres
 *
 * Original coding 1998, Jan Wieck.  Heavily revised 2003, Tom Lane.
 *
 * Copyright (c) 1998-2021, PostgreSQL Global Development Group
 *
 * src/include/utils/numeric.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _PG_NUMERIC_H_
#define _PG_NUMERIC_H_

#include "fmgr.h"

/*
 * Limit on the precision (and hence scale) specifiable in a NUMERIC typmod.
 * Note that the implementation limit on the length of a numeric value is
 * much larger --- beware of what you use this for!
 */
#define NUMERIC_MAX_PRECISION		1000

/*
 * Internal limits on the scales chosen for calculation results
 */
#define NUMERIC_MAX_DISPLAY_SCALE	NUMERIC_MAX_PRECISION
#define NUMERIC_MIN_DISPLAY_SCALE	0

#define NUMERIC_MAX_RESULT_SCALE	(NUMERIC_MAX_PRECISION * 2)

/*
 * For inherently inexact calculations such as division and square root,
 * we try to get at least this many significant digits; the idea is to
 * deliver a result no worse than float8 would.
 */
#define NUMERIC_MIN_SIG_DIGITS		16

/* The actual contents of Numeric are private to numeric.c */
struct NumericData;
typedef struct NumericData *Numeric;

/* Enum type for bigint aggregates for tsql dialect */
typedef enum tsqlAggType {
	TSQL_SUM,
	TSQL_AVG
} tsqlAggType;

/*
 * fmgr interface macros
 */

#define DatumGetNumeric(X)		  ((Numeric) PG_DETOAST_DATUM(X))
#define DatumGetNumericCopy(X)	  ((Numeric) PG_DETOAST_DATUM_COPY(X))
#define NumericGetDatum(X)		  PointerGetDatum(X)
#define PG_GETARG_NUMERIC(n)	  DatumGetNumeric(PG_GETARG_DATUM(n))
#define PG_GETARG_NUMERIC_COPY(n) DatumGetNumericCopy(PG_GETARG_DATUM(n))
#define PG_RETURN_NUMERIC(x)	  return NumericGetDatum(x)

/*
 * Utility functions in numeric.c
 */
extern bool numeric_is_nan(Numeric num);
extern bool numeric_is_inf(Numeric num);
int32		numeric_maximum_size(int32 typmod);
extern char *numeric_out_sci(Numeric num, int scale);
extern char *numeric_normalize(Numeric num);

extern Numeric int64_to_numeric(int64 val);
extern Numeric int64_div_fast_to_numeric(int64 val1, int log10val2);

extern Numeric numeric_add_opt_error(Numeric num1, Numeric num2,
									 bool *have_error);
extern Numeric numeric_sub_opt_error(Numeric num1, Numeric num2,
									 bool *have_error);
extern Numeric numeric_mul_opt_error(Numeric num1, Numeric num2,
									 bool *have_error);
extern Numeric numeric_div_opt_error(Numeric num1, Numeric num2,
									 bool *have_error);
extern Numeric numeric_mod_opt_error(Numeric num1, Numeric num2,
									 bool *have_error);
extern int32 numeric_int4_opt_error(Numeric num, bool *error);

extern Datum bigint_poly_aggr_final(FunctionCallInfo fcinfo, tsqlAggType aggType);

/* Hook interface to calculate exact numeric digits before generating numeric overflow error in TSQL */
typedef bool (*detect_numeric_overflow_hook_type) (int weight, int dscale, int first_block, int numeric_base);
extern PGDLLIMPORT detect_numeric_overflow_hook_type detect_numeric_overflow_hook;

#endif							/* _PG_NUMERIC_H_ */
