/*-------------------------------------------------------------------------
 *
 * queryenvironment.h
 *	  Access to functions to mutate the query environment and retrieve the
 *	  actual data related to entries (if any).
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/utils/queryenvironment.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef QUERYENVIRONMENT_H
#define QUERYENVIRONMENT_H

#include "access/tupdesc.h"
#include "access/htup.h"
#include "access/skey.h"
#include "utils/memutils.h"
#include "utils/relcache.h"
#include "storage/sinval.h"


typedef enum EphemeralNameRelationType
{
	ENR_NAMED_TUPLESTORE,		/* named tuplestore relation; e.g., deltas */
	ENR_TSQL_TEMP		/* Temp table created in procedure/function */
} EphemeralNameRelationType;

typedef enum ENRCatalogTupleType
{
	ENR_CATTUP_CLASS = 0,
	ENR_CATTUP_TYPE,
	ENR_CATTUP_ARRAYTYPE,
	ENR_CATTUP_ATTRIBUTE,
	ENR_CATTUP_CONSTRAINT,
	ENR_CATTUP_STATISTIC,
	ENR_CATTUP_STATISTIC_EXT,
	ENR_CATTUP_STATISTIC_EXT_DATA,
	ENR_CATTUP_DEPEND,
	ENR_CATTUP_SHDEPEND,
	ENR_CATTUP_INDEX,
	ENR_CATTUP_SEQUENCE,
	ENR_CATTUP_ATTR_DEF_REL,
	ENR_CATTUP_END,
} ENRCatalogTupleType;

typedef enum ENRTupleOperationType
{
	ENR_OP_ADD,
	ENR_OP_UPDATE,
	ENR_OP_DROP
} ENRTupleOperationType;

/*
 * This struct stores all information needed to restore the tuple on ROLLBACK. 
 */
typedef struct ENRUncommittedTupleData
{
	/* Oid of catalog this this tuple belongs to */
	Oid							catalog_oid;
	/* Operation */
	ENRTupleOperationType		optype;
	/* A copy of the tuple itself */
	HeapTuple 					tup;
	/* Track if this was created in a specific subtransactionid so that it can be rolled back on savepoints. */
	SubTransactionId subid;
} ENRUncommittedTupleData;

typedef ENRUncommittedTupleData *ENRUncommittedTuple;

/*
 * Some ephemeral named relations must match some relation (e.g., trigger
 * transition tables), so to properly handle cached plans and DDL, we should
 * carry the OID of that relation.  In other cases an ENR might be independent
 * of any relation which is stored in the system catalogs, so we need to be
 * able to directly store the TupleDesc.  We never need both.
 */
typedef struct EphemeralNamedRelationMetadataData
{
	char	   *name;			/* name used to identify the relation */

	/* only one of the next two fields should be used */
	Oid			reliddesc;		/* oid of relation to get tupdesc */
	TupleDesc	tupdesc;		/* description of result rows */

	EphemeralNameRelationType enrtype;	/* to identify type of relation */
	double		enrtuples;		/* estimated number of tuples */
	List		*cattups[ENR_CATTUP_END];

	/* We must ignore transaction semantics for table variables. */
	bool		is_bbf_temp_table;
	/* We don't need to track uncommitted ENRs as they would be dropped entirely on ROLLBACK. */
	bool		is_committed;
	/* If this ENR is currently being rolled back, don't track changes to it. */
	bool		in_rollback;
	/* Track if this was created/dropped in a specific subtransactionid so that it can be rolled back on savepoints. */
	SubTransactionId created_subid;
	SubTransactionId dropped_subid;
	/* List of uncommitted tuples. They must be processed on ROLLBACK, or cleared on commit. */
	List		*uncommitted_cattups[ENR_CATTUP_END];
} EphemeralNamedRelationMetadataData;

typedef EphemeralNamedRelationMetadataData *EphemeralNamedRelationMetadata;

/*
 * Ephemeral Named Relation data; used for parsing named relations not in the
 * catalog, like transition tables in AFTER triggers.
 */
typedef struct EphemeralNamedRelationData
{
	EphemeralNamedRelationMetadataData md;
	void	   *reldata;		/* structure for execution-time access to data */
} EphemeralNamedRelationData;

typedef EphemeralNamedRelationData *EphemeralNamedRelation;

/*
 * This is an opaque structure outside of queryenvironment.c itself.  The
 * intention is to be able to change the implementation or add new context
 * features without needing to change existing code for use of existing
 * features.
 */
typedef struct QueryEnvironment QueryEnvironment;

extern struct QueryEnvironment *currentQueryEnv;
extern struct QueryEnvironment *topLevelQueryEnv;

extern QueryEnvironment *create_queryEnv(void);
extern PGDLLEXPORT QueryEnvironment *create_queryEnv2(MemoryContext cxt, bool top_level);
extern PGDLLEXPORT void remove_queryEnv(void);
extern EphemeralNamedRelationMetadata get_visible_ENR_metadata(QueryEnvironment *queryEnv, const char *refname);
extern void register_ENR(QueryEnvironment *queryEnv, EphemeralNamedRelation enr);
extern void unregister_ENR(QueryEnvironment *queryEnv, const char *name);
extern PGDLLEXPORT List *get_namedRelList(void);
extern EphemeralNamedRelation get_ENR(QueryEnvironment *queryEnv, const char *name, bool search);
extern PGDLLEXPORT EphemeralNamedRelation get_ENR_withoid(QueryEnvironment *queryEnv, Oid oid, EphemeralNameRelationType type);
extern EphemeralNamedRelation GetENRTempTableWithOid(Oid id);
extern TupleDesc ENRMetadataGetTupDesc(EphemeralNamedRelationMetadata enrmd);
extern bool ENRGetSystableScan(Relation rel, Oid indexoid, int nkeys, ScanKey key, List **tuplist, int *tuplist_i, int *tuplist_flags);
extern bool ENRAddTuple(Relation rel, HeapTuple tup);
extern bool ENRDropTuple(Relation rel, HeapTuple tup);
extern bool ENRUpdateTuple(Relation rel, HeapTuple tup);

extern void ENRDropEntry(Oid id);
extern PGDLLEXPORT void ENRDropTempTables(QueryEnvironment *queryEnv);
extern void ENRDropCatalogEntry(Relation catalog_relation, Oid relid);

/* ENR Rollback functions */
extern bool ENRTupleIsDropped(Relation rel, HeapTuple tup);
extern void ENRCommitChanges(QueryEnvironment *queryEnv);
extern void ENRRollbackChanges(QueryEnvironment *queryEnv);
extern void ENRRollbackSubtransaction(SubTransactionId subid, QueryEnvironment *queryEnv);

/* Temp Table Cache Inval */
extern void SaveCatcacheMessage(int cacheId, uint32 hashValue, Oid dbId);
extern void ClearSavedCatcacheMessages(void);
extern bool SIMessageIsForTempTable(const SharedInvalidationMessage *msg);

/* Various checks */
extern bool IsTsqlTableVariable(Relation rel);
extern bool IsTsqlTempTable(char relpersistence);
extern bool UseTempOidBuffer(void);
extern bool UseTempOidBufferForOid(Oid relId);
extern bool has_existing_enr_relations(void);

/* Hooks */
typedef EphemeralNamedRelation (*pltsql_get_tsql_enr_from_oid_hook_type) (Oid oid);
extern PGDLLIMPORT pltsql_get_tsql_enr_from_oid_hook_type pltsql_get_tsql_enr_from_oid_hook;

#endif							/* QUERYENVIRONMENT_H */
