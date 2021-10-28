/*-------------------------------------------------------------------------
 *
 * sequence.h
 *	  prototypes for sequence.c.
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/sequence.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef SEQUENCE_H
#define SEQUENCE_H

#include "access/xlogreader.h"
#include "catalog/objectaddress.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "nodes/parsenodes.h"
#include "parser/parse_node.h"
#include "storage/relfilenode.h"


/* Sequence validate increment hook */
typedef void (*pltsql_sequence_validate_increment_hook_type) (int64 increment_by,
																int64 max_value,
																int64 min_value);
extern PGDLLIMPORT pltsql_sequence_validate_increment_hook_type pltsql_sequence_validate_increment_hook;

/* Sequence datatype hook */
typedef void (*pltsql_sequence_datatype_hook_type) (ParseState *pstate,
														Oid *newtypid,
														bool for_identity,
														DefElem *as_type,
														DefElem **max_value,
														DefElem **min_value);
extern PGDLLIMPORT pltsql_sequence_datatype_hook_type pltsql_sequence_datatype_hook;

/* Sequence nextval hook */
typedef void (*pltsql_nextval_hook_type) (Oid seqid, int64 val);
extern PGDLLIMPORT pltsql_nextval_hook_type pltsql_nextval_hook;

/* Sequence reset cache hook */
typedef void (*pltsql_resetcache_hook_type) ();
extern PGDLLIMPORT pltsql_resetcache_hook_type pltsql_resetcache_hook;

typedef struct FormData_pg_sequence_data
{
	int64		last_value;
	int64		log_cnt;
	bool		is_called;
} FormData_pg_sequence_data;

typedef FormData_pg_sequence_data *Form_pg_sequence_data;

/*
 * Columns of a sequence relation
 */

#define SEQ_COL_LASTVAL			1
#define SEQ_COL_LOG				2
#define SEQ_COL_CALLED			3

#define SEQ_COL_FIRSTCOL		SEQ_COL_LASTVAL
#define SEQ_COL_LASTCOL			SEQ_COL_CALLED

/* XLOG stuff */
#define XLOG_SEQ_LOG			0x00

typedef struct xl_seq_rec
{
	RelFileNode node;
	/* SEQUENCE TUPLE DATA FOLLOWS AT THE END */
} xl_seq_rec;

extern int64 nextval_internal(Oid relid, bool check_permissions);
extern Datum nextval(PG_FUNCTION_ARGS);
extern List *sequence_options(Oid relid);

extern ObjectAddress DefineSequence(ParseState *pstate, CreateSeqStmt *stmt);
extern ObjectAddress AlterSequence(ParseState *pstate, AlterSeqStmt *stmt);
extern void DeleteSequenceTuple(Oid relid);
extern void ResetSequence(Oid seq_relid);
extern void ResetSequenceCaches(void);

extern void seq_redo(XLogReaderState *rptr);
extern void seq_desc(StringInfo buf, XLogReaderState *rptr);
extern const char *seq_identify(uint8 info);
extern void seq_mask(char *pagedata, BlockNumber blkno);

#endif							/* SEQUENCE_H */
