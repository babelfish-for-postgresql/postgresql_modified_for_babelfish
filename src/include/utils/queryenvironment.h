/*-------------------------------------------------------------------------
 *
 * queryenvironment.h
 *	  Access to functions to mutate the query environment and retrieve the
 *	  actual data related to entries (if any).
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
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
	ENR_CATTUP_END
} ENRCatalogTupleType;

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
extern QueryEnvironment *create_queryEnv2(MemoryContext cxt, bool top_level);
extern void remove_queryEnv(void);
extern EphemeralNamedRelationMetadata get_visible_ENR_metadata(QueryEnvironment *queryEnv, const char *refname);
extern void register_ENR(QueryEnvironment *queryEnv, EphemeralNamedRelation enr);
extern void unregister_ENR(QueryEnvironment *queryEnv, const char *name);
extern List *get_namedRelList(void);
extern EphemeralNamedRelation get_ENR(QueryEnvironment *queryEnv, const char *name);
extern EphemeralNamedRelation get_ENR_withoid(QueryEnvironment *queryEnv, Oid oid);
extern TupleDesc ENRMetadataGetTupDesc(EphemeralNamedRelationMetadata enrmd);
extern bool ENRaddTuple(Relation rel, HeapTuple tup);
extern bool ENRdropTuple(Relation rel, HeapTuple tup);
extern bool ENRupdateTuple(Relation rel, HeapTuple tup);
extern bool ENRgetSystableScan(Relation rel, Oid indexoid, int nkeys, ScanKey key, List **tuplist, int *tuplist_i);
extern void ENRDropTempTables(QueryEnvironment *queryEnv);
extern void ENRDropEntry(Oid id);

#endif							/* QUERYENVIRONMENT_H */
