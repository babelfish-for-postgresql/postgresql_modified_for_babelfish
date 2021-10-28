/*-------------------------------------------------------------------------
 *
 * queryenvironment.c
 *	  Query environment, to store context-specific values like ephemeral named
 *	  relations.  Initial use is for named tuplestores for delta information
 *	  from "normal" relations.
 *
 * The initial implementation uses a list because the number of such relations
 * in any one context is expected to be very small.  If that becomes a
 * performance problem, the implementation can be changed with no other impact
 * on callers, since this is an opaque structure.  This is the reason to
 * require a create function.
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/misc/queryenvironment.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup.h"
#include "access/table.h"
#include "access/tupdesc.h"
#include "access/htup_details.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_statistic.h"
#include "catalog/pg_statistic_ext.h"
#include "catalog/pg_type.h"
#include "parser/parser.h"      /* only needed for GUC variables */
#include "utils/inval.h"
#include "utils/syscache.h"
#include "utils/queryenvironment.h"
#include "utils/rel.h"

/*
 * Private state of a query environment.
 */
struct QueryEnvironment
{
	List	   *namedRelList;
	struct QueryEnvironment *parentEnv;
	MemoryContext	memctx;
};

struct QueryEnvironment topLevelQueryEnvData;
struct QueryEnvironment *topLevelQueryEnv = &topLevelQueryEnvData;
struct QueryEnvironment *currentQueryEnv = NULL;

typedef enum ENRTupleOperationType
{
	ENR_OP_ADD,
	ENR_OP_UPDATE,
	ENR_OP_DROP
} ENRTupleOperationType;

QueryEnvironment *
create_queryEnv(void)
{
	return (QueryEnvironment *) palloc0(sizeof(QueryEnvironment));
}

/* 
 * Same as create_queryEnv but takes 2 additional arguments for the caller to
 * indicate the desired memory context to use, and if this is the top level
 * query environment it wants to create.
 */
QueryEnvironment *
create_queryEnv2(MemoryContext cxt, bool top_level)
{
	MemoryContext			oldcxt;
	QueryEnvironment		*queryEnv;

	if (top_level) {
		queryEnv = topLevelQueryEnv;
		queryEnv->namedRelList = NIL;
		queryEnv->parentEnv = NULL;
		queryEnv->memctx = cxt;
	} else {
		oldcxt = MemoryContextSwitchTo(cxt);
		queryEnv = (QueryEnvironment *) palloc0(sizeof(QueryEnvironment));
		queryEnv->parentEnv = currentQueryEnv;
		queryEnv->memctx = cxt;
		MemoryContextSwitchTo(oldcxt);
	}

	currentQueryEnv = queryEnv;
	return queryEnv;
}

/* Remove the current query environment and make its parent current. */
void remove_queryEnv() {
	MemoryContext			oldcxt;
	QueryEnvironment		*tmp;

	/* We should never "free" top level query env as it's in stack memory. */
	if (!currentQueryEnv || currentQueryEnv == topLevelQueryEnv)
		return;

	tmp = currentQueryEnv->parentEnv;
	oldcxt = MemoryContextSwitchTo(currentQueryEnv->memctx);
	pfree(currentQueryEnv);
	MemoryContextSwitchTo(oldcxt);

	currentQueryEnv = tmp;
}

EphemeralNamedRelationMetadata
get_visible_ENR_metadata(QueryEnvironment *queryEnv, const char *refname)
{
	EphemeralNamedRelation enr;

	Assert(refname != NULL);

	if (queryEnv == NULL)
		return NULL;

	enr = get_ENR(queryEnv, refname);
	if (enr)
		return &(enr->md);

	return NULL;
}

/*
 * Register a named relation for use in the given environment.
 *
 * If this is intended exclusively for planning purposes, the tstate field can
 * be left NULL;
 */
void
register_ENR(QueryEnvironment *queryEnv, EphemeralNamedRelation enr)
{
	Assert(enr != NULL);
	Assert(get_ENR(queryEnv, enr->md.name) == NULL);

	queryEnv->namedRelList = lappend(queryEnv->namedRelList, enr);
}

/*
 * Unregister an ephemeral relation by name.  This will probably be a rarely
 * used function, but seems like it should be provided "just in case".
 */
void
unregister_ENR(QueryEnvironment *queryEnv, const char *name)
{
	EphemeralNamedRelation match;

	match = get_ENR(queryEnv, name);
	if (match)
		queryEnv->namedRelList = list_delete(queryEnv->namedRelList, match);
}

/*
 * Return the list of ENRs registered in the current query environment.
 */
List *get_namedRelList()
{
	return currentQueryEnv->namedRelList;
}

/*
 * This returns an ENR if there is a name match in the given collection.  It
 * must quietly return NULL if no match is found.
 */
EphemeralNamedRelation
get_ENR(QueryEnvironment *queryEnv, const char *name)
{
	ListCell   *lc;

	Assert(name != NULL);

	if (queryEnv == NULL)
		return NULL;

	foreach(lc, queryEnv->namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		if (strcmp(enr->md.name, name) == 0)
			return enr;
	}

	return NULL;
}

/*
 * Same as get_ENR() but just search for relation oid
 */
EphemeralNamedRelation
get_ENR_withoid(QueryEnvironment *queryEnv, Oid id)
{
	ListCell   *lc;

	if (queryEnv == NULL)
		return NULL;

	foreach(lc, queryEnv->namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		if (enr->md.reliddesc == id)
			return enr;
	}

	return NULL;
}

/*
 * Gets the TupleDesc for a Ephemeral Named Relation, based on which field was
 * filled.
 *
 * When the TupleDesc is based on a relation from the catalogs, we count on
 * that relation being used at the same time, so that appropriate locks will
 * already be held.  Locking here would be too late anyway.
 */
TupleDesc
ENRMetadataGetTupDesc(EphemeralNamedRelationMetadata enrmd)
{
	TupleDesc	tupdesc;

	/* One, and only one, of these fields must be filled. */
	Assert((enrmd->reliddesc == InvalidOid) != (enrmd->tupdesc == NULL));

	if (enrmd->tupdesc != NULL)
		tupdesc = enrmd->tupdesc;
	else
	{
		Relation	relation;

		relation = table_open(enrmd->reliddesc, NoLock);
		tupdesc = relation->rd_att;
		table_close(relation, NoLock);
	}

	return tupdesc;
}

/*
 * Get the starting tuple (or more precisely, a ListCell that contains the tuple) 
 * for systable scan functions based on the given keys.
 *
 * Returns true if we have found a qualified tuple and stored in *tuplist and *tuplist_i.
 */
bool ENRgetSystableScan(Relation rel, Oid indexId, int nkeys, ScanKey key, List **tuplist, int *tuplist_i)
{
	QueryEnvironment *queryEnv = currentQueryEnv;
	Oid reloid;
	Datum v1 = 0, v2 = 0, v3 = 0, v4 = 0;

	if (sql_dialect != SQL_DIALECT_TSQL)
		return false;

	reloid = RelationGetRelid(rel);

	if (reloid != RelationRelationId && reloid != TypeRelationId && 
				reloid != AttributeRelationId && 
				reloid != ConstraintRelationId && 
				reloid != StatisticRelationId &&
				reloid != StatisticExtRelationId)
		return NULL;

	switch (nkeys) {
		case 4:
			v4 = key[3].sk_argument;
			v3 = key[2].sk_argument;
			v2 = key[1].sk_argument;
			v1 = key[0].sk_argument;
			break;
		case 3:
			v3 = key[2].sk_argument;
			v2 = key[1].sk_argument;
			v1 = key[0].sk_argument;
			break;
		case 2:
			v2 = key[1].sk_argument;
			v1 = key[0].sk_argument;
			break;
		case 1:
			v1 = key[0].sk_argument;
			break;
		default:
			break;
	}
	if (!v1 && !v2 && !v3 && !v4)
		return false;

	while (queryEnv)
	{
		ListCell   *lc;

		foreach(lc, queryEnv->namedRelList)
		{
			EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);
			if (enr->md.enrtype != ENR_TSQL_TEMP)
				continue;

			if (reloid == RelationRelationId) {
				if (indexId == ClassOidIndexId) {
					if (enr->md.reliddesc == (Oid)v1) {
						*tuplist = enr->md.cattups[ENR_CATTUP_CLASS];
						*tuplist_i = 0;
						return true;
					}
				}
				else if (indexId == ClassNameNspIndexId) {
					if (enr->md.name && strcmp(enr->md.name, (char*)v1) == 0) {
						*tuplist = enr->md.cattups[ENR_CATTUP_CLASS];
						*tuplist_i = 0;
						return true;
					}
				}
			}
			else if (reloid == TypeRelationId)
			{
				ListCell *type_lc = list_head(enr->md.cattups[ENR_CATTUP_TYPE]);
				ListCell *arraytype_lc = list_head(enr->md.cattups[ENR_CATTUP_ARRAYTYPE]);
				if (indexId == TypeOidIndexId) {
					/* Composite type */
					if (type_lc && ((Form_pg_type) GETSTRUCT((HeapTuple)lfirst(type_lc)))->oid == (Oid)v1) {
						*tuplist = enr->md.cattups[ENR_CATTUP_TYPE];
						*tuplist_i = 0;
						return true;
					}
					/* Array type */
					else if (arraytype_lc && ((Form_pg_type) GETSTRUCT((HeapTuple)lfirst(arraytype_lc)))->oid == (Oid)v1) {
						*tuplist = enr->md.cattups[ENR_CATTUP_ARRAYTYPE];
						*tuplist_i = 0;
						return true;
					}
				} else if (indexId == TypeNameNspIndexId) {
					/* Composite type */
					if (type_lc && strcmp(((Form_pg_type) GETSTRUCT((HeapTuple)lfirst(type_lc)))->typname.data, (char*)v1) == 0) {
						*tuplist = enr->md.cattups[ENR_CATTUP_TYPE];
						*tuplist_i = 0;
						return true;
					} 
					/* Array type */
					else if (arraytype_lc && strcmp(((Form_pg_type) GETSTRUCT((HeapTuple)lfirst(arraytype_lc)))->typname.data, (char*)v1) == 0) {
						*tuplist = enr->md.cattups[ENR_CATTUP_ARRAYTYPE];
						*tuplist_i = 0;
						return true;
					}
				}
			}
			else if (reloid == AttributeRelationId)
			{
				ListCell   *lc2;
				if (enr->md.reliddesc == (Oid)v1)
				{
					if (nkeys == 1) {
						*tuplist = enr->md.cattups[ENR_CATTUP_ATTRIBUTE];
						*tuplist_i = 0;
						return true;
					}
					foreach(lc2, enr->md.cattups[ENR_CATTUP_ATTRIBUTE]) {
						Form_pg_attribute tupform = (Form_pg_attribute) GETSTRUCT((HeapTuple) lfirst(lc2));
						if (indexId == AttributeRelidNumIndexId && (int)v2 <= tupform->attnum) {
							*tuplist = enr->md.cattups[ENR_CATTUP_ATTRIBUTE];
							*tuplist_i = foreach_current_index(lc2);
							return true;
						} else if (indexId == AttributeRelidNameIndexId && strcmp((char*)v2, tupform->attname.data) == 0) {
							*tuplist = enr->md.cattups[ENR_CATTUP_ATTRIBUTE];
							*tuplist_i = foreach_current_index(lc2);
							return true;
						}
					}
				}
			}
			else if (reloid == ConstraintRelationId)
			{
				/*
				 * XXX: There are multiple combinations of search keys for ConstraintRelidTypidNameIndexId
				 * but we seem to only need one. Ideally we should support all.
				 */
				if (nkeys == 1 && indexId == ConstraintRelidTypidNameIndexId)
				{
					if (enr->md.reliddesc == (Oid)v1) {
						*tuplist = enr->md.cattups[ENR_CATTUP_CONSTRAINT];
						*tuplist_i = 0;
						return true;
					}
				}
				else if (indexId == ConstraintOidIndexId) {
					ListCell   *lc2;
					foreach(lc2, enr->md.cattups[ENR_CATTUP_CONSTRAINT]) {
						Form_pg_constraint tupform = (Form_pg_constraint) GETSTRUCT((HeapTuple) lfirst(lc2));
						if (indexId == ConstraintOidIndexId && tupform->oid == (Oid)v1) {
							*tuplist = enr->md.cattups[ENR_CATTUP_CONSTRAINT];
							*tuplist_i = foreach_current_index(lc2);
							return true;
						} else if (indexId == ConstraintTypidIndexId && tupform->contypid == (Oid)v1) {
							*tuplist = enr->md.cattups[ENR_CATTUP_CONSTRAINT];
							*tuplist_i = foreach_current_index(lc2);
							return true;
						} else if (indexId == ConstraintParentIndexId && tupform->conparentid == (Oid)v1) {
							*tuplist = enr->md.cattups[ENR_CATTUP_CONSTRAINT];
							*tuplist_i = foreach_current_index(lc2);
							return true;
						} else if (indexId == ConstraintNameNspIndexId && strcmp(tupform->conname.data, (char*)v1) == 0) {
							*tuplist = enr->md.cattups[ENR_CATTUP_CONSTRAINT];
							*tuplist_i = foreach_current_index(lc2);
							return true;
						}
					}
				}
			}
			else if (reloid == StatisticRelationId)
			{
				/* 
				 * pg_statistic has only one index StatisticRelidAttnumInhIndexId
				 * which always has the relation id (starelid) as the first key.
				 */
				if (enr->md.reliddesc != (Oid)v1)
					return false;

				if (nkeys == 1) {
					*tuplist = enr->md.cattups[ENR_CATTUP_STATISTIC];
					*tuplist_i = 0;
					return true;
				} else {
					ListCell   *lc2;
					foreach(lc2, enr->md.cattups[ENR_CATTUP_STATISTIC]) {
						Form_pg_statistic tupform = (Form_pg_statistic) GETSTRUCT((HeapTuple) lfirst(lc2));
						if (tupform->staattnum == (int16)v2) {
							*tuplist = enr->md.cattups[ENR_CATTUP_STATISTIC];
							*tuplist_i = foreach_current_index(lc2);
							return true;
						}
					}
				}
			}
			else if (reloid == StatisticExtRelationId)
			{
				ListCell   *lc2;
				if (indexId == StatisticExtRelidIndexId && enr->md.reliddesc == (Oid)v1) {
					*tuplist = enr->md.cattups[ENR_CATTUP_STATISTIC_EXT];
					*tuplist_i = 0;
					return true;
				}

				foreach(lc2, enr->md.cattups[ENR_CATTUP_STATISTIC_EXT]) {
					Form_pg_statistic_ext tupform = (Form_pg_statistic_ext) GETSTRUCT((HeapTuple) lfirst(lc2));
					if (indexId == StatisticExtOidIndexId && tupform->oid == (Oid)v1) {
						*tuplist = enr->md.cattups[ENR_CATTUP_STATISTIC_EXT];
						*tuplist_i = 0;
						return true;
					}
					else if (indexId == StatisticExtNameIndexId && strcmp(tupform->stxname.data, (char*)v1)) {
						*tuplist = enr->md.cattups[ENR_CATTUP_STATISTIC_EXT];
						*tuplist_i = 0;
						return true;
					}
				}
			}
		}
		queryEnv = queryEnv->parentEnv;
	}
	return false;
}

/*
 * Workhorse for add/update/drop tuples in the ENR.
 *
 * Return true if the asked operation is done.
 * Return false if the asked operation is not possible.
 */
static bool _ENR_tuple_operation(Relation catalog_rel, HeapTuple tup, ENRTupleOperationType op)
{
	EphemeralNamedRelation	enr = NULL;
	HeapTuple				oldtup, newtup;
	MemoryContext			oldcxt;
	Oid						catalog_oid, rel_oid;
	HeapTuple				tmp;
	bool					ret = false;
	List					**list_ptr = NULL;
	ListCell				*lc = NULL;
	QueryEnvironment		*queryEnv = currentQueryEnv;
	int                      insert_at = 0;

	if (sql_dialect != SQL_DIALECT_TSQL)
		return false;

	catalog_oid = RelationGetRelid(catalog_rel);

	while (queryEnv && !ret)
	{
		switch (catalog_oid) {
			case RelationRelationId:
				rel_oid = ((Form_pg_class) GETSTRUCT(tup))->oid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid))) {
					list_ptr = &enr->md.cattups[ENR_CATTUP_CLASS];
					lc = list_head(enr->md.cattups[ENR_CATTUP_CLASS]);
					ret = true;
				}
				break;
			case TypeRelationId:
				/* Composite type */
				if (((Form_pg_type) GETSTRUCT(tup))->typelem == InvalidOid) {
					rel_oid = ((Form_pg_type) GETSTRUCT(tup))->typrelid;
					if ((enr = get_ENR_withoid(queryEnv, rel_oid))) {
						list_ptr = &enr->md.cattups[ENR_CATTUP_TYPE];
						lc = list_head(enr->md.cattups[ENR_CATTUP_TYPE]);
						ret = true;
					}
				/* Array type */
				} else {
					/* 
					 * Arraytype tuple is a bit special since it doesn't carry the 
					 * relation OID but it carries the relation's composite type OID.
					 */
					ListCell   *curlc;
					foreach(curlc, queryEnv->namedRelList) {
						EphemeralNamedRelation tmp_enr;
						ListCell *type_lc;
        
						tmp_enr = (EphemeralNamedRelation) lfirst(curlc);
						type_lc = list_head(tmp_enr->md.cattups[ENR_CATTUP_TYPE]);
						if (type_lc && ((Form_pg_type) GETSTRUCT((HeapTuple)lfirst(type_lc)))->oid 
										== ((Form_pg_type) GETSTRUCT(tup))->typelem) {
							enr = tmp_enr;
							break;
						}
					}
					if (enr) {
						list_ptr = &enr->md.cattups[ENR_CATTUP_ARRAYTYPE];
						lc = list_head(enr->md.cattups[ENR_CATTUP_ARRAYTYPE]);
						ret = true;
					}
				}
				break;
			case AttributeRelationId:
				rel_oid = ((Form_pg_attribute) GETSTRUCT(tup))->attrelid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid))) {
					ListCell *curlc;
					Form_pg_attribute tf1, tf2; /* tuple forms*/
        
					list_ptr = &enr->md.cattups[ENR_CATTUP_ATTRIBUTE];
					tf1 = (Form_pg_attribute) GETSTRUCT((HeapTuple)tup);
					foreach(curlc, enr->md.cattups[ENR_CATTUP_ATTRIBUTE]) {
						tf2 = (Form_pg_attribute) GETSTRUCT((HeapTuple)lfirst(curlc));
						/*
						 * The attributes tuples are sorted increasingly based
						 * on the attribute number. However, we should keep
						 * user attributes(attnum>0) in front of system
						 * attributes just like how they appear in pg_attributes.
						 */
						if ((tf1->attnum > 0 && (tf2->attnum >= tf1->attnum || tf2->attnum <= 0)) || 
								(tf1->attnum <= 0 && tf2->attnum <= tf1->attnum)) {
							lc = curlc;
							insert_at = foreach_current_index(curlc);
							break;
						}
						insert_at = foreach_current_index(curlc) + 1;
					}
					ret = true;
				}
				break;
			case ConstraintRelationId:
				rel_oid = ((Form_pg_constraint) GETSTRUCT(tup))->conrelid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid))) {
					Form_pg_constraint tf1, tf2; /* tuple forms*/
					ListCell *curlc;
        
					list_ptr = &enr->md.cattups[ENR_CATTUP_CONSTRAINT];
					tf1 = (Form_pg_constraint) GETSTRUCT(tup);
					foreach(curlc, enr->md.cattups[ENR_CATTUP_CONSTRAINT]) {
						tf2 = (Form_pg_constraint) GETSTRUCT((HeapTuple) lfirst(curlc));
						if (tf2->oid >= tf1->oid) {
							lc = curlc;
							insert_at = foreach_current_index(curlc) + 1;
							break;
						}
					}
					ret = true;
				}
				break;
			case StatisticRelationId:
				rel_oid = ((Form_pg_statistic) GETSTRUCT(tup))->starelid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid))) {
					Form_pg_statistic tf1, tf2; /* tuple forms*/
					ListCell *curlc;
        
					list_ptr = &enr->md.cattups[ENR_CATTUP_STATISTIC];
					tf1 = (Form_pg_statistic) GETSTRUCT(tup);
					foreach(curlc, enr->md.cattups[ENR_CATTUP_STATISTIC]) {
						tf2 = (Form_pg_statistic) GETSTRUCT((HeapTuple) lfirst(curlc));
						if (tf2->staattnum >= tf1->staattnum) {
							lc = curlc;
							insert_at = foreach_current_index(curlc) + 1;
							break;
						}
					}
					ret = true;
				}
				break;
			case StatisticExtRelationId:
				rel_oid = ((Form_pg_statistic_ext) GETSTRUCT(tup))->stxrelid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid))) {
					Form_pg_statistic_ext tf1, tf2; /* tuple forms*/
					ListCell *curlc;
        
					list_ptr = &enr->md.cattups[ENR_CATTUP_STATISTIC_EXT];
					tf1 = (Form_pg_statistic_ext) GETSTRUCT(tup);
					foreach(curlc, enr->md.cattups[ENR_CATTUP_STATISTIC_EXT]) {
						tf2 = (Form_pg_statistic_ext) GETSTRUCT((HeapTuple) lfirst(curlc));
						if (tf2->oid >= tf1->oid) {
							lc = curlc;
							insert_at = foreach_current_index(curlc) + 1;
							break;
						}
					}
					ret = true;
				}
				break;
			default:
				break;
		}
		/* add/drop/update is possible. Do it now. */
		if (ret) {
			Assert(queryEnv->memctx);
			oldcxt = MemoryContextSwitchTo(queryEnv->memctx);
			switch (op) {
				case ENR_OP_ADD:
					newtup = heap_copytuple(tup);
					*list_ptr = list_insert_nth(*list_ptr, insert_at, newtup);
					CacheInvalidateHeapTuple(catalog_rel, newtup, NULL);
					break;
				case ENR_OP_UPDATE:
					oldtup = lfirst(lc);
					lfirst(lc) = heap_copytuple(tup);
					CacheInvalidateHeapTuple(catalog_rel, oldtup, tup);
					break;
				case ENR_OP_DROP:
					tmp = lfirst(lc);
					*list_ptr = list_delete_ptr(*list_ptr, tmp);
					CacheInvalidateHeapTuple(catalog_rel, tup, NULL); 
					heap_freetuple(tmp);
					break;
				default:
					break;
			}
			MemoryContextSwitchTo(oldcxt);
		}
		queryEnv = queryEnv->parentEnv;
	}

	return ret;
}

/*
 * Add tuple to an ENR. It assumes that an ENR entry has been created with
 * the relation name and relation oid.
 */
bool ENRaddTuple(Relation rel, HeapTuple tup)
{
	return _ENR_tuple_operation(rel, tup, ENR_OP_ADD);
}

/*
 * Drop tuple of an ENR. 
 * We shouldn't assume the origin of the input tuples (i.e. whether it comes 
 * from the ENR itself) so we need to search in ENR based on the given tuple.
 */
bool ENRdropTuple(Relation rel, HeapTuple tup)
{
	return _ENR_tuple_operation(rel, tup, ENR_OP_DROP);
}

/*
 * Update tuple of an ENR.
 */
bool ENRupdateTuple(Relation rel, HeapTuple tup)
{
	return _ENR_tuple_operation(rel, tup, ENR_OP_UPDATE);
}

/*
 * Drop an ENR entry and delete it from the registered list.
 */
void ENRDropEntry(Oid id)
{
	EphemeralNamedRelation	enr;
	MemoryContext oldcxt;

	if (sql_dialect != SQL_DIALECT_TSQL || !currentQueryEnv)
		return;

	if ((enr = get_ENR_withoid(currentQueryEnv, id)) == NULL)
		return;

	oldcxt = MemoryContextSwitchTo(currentQueryEnv->memctx);
	currentQueryEnv->namedRelList = list_delete(currentQueryEnv->namedRelList, enr);
	pfree(enr->md.name);
	pfree(enr);
	MemoryContextSwitchTo(oldcxt);
}

/*
 * Drop all the temp tables registered as ENR in the given query environment.
 */
void
ENRDropTempTables(QueryEnvironment *queryEnv)
{
	ListCell   *lc = NULL;
	ObjectAddress object;

	if (!queryEnv)
		return;

	object.classId = RelationRelationId;
	object.objectSubId = 0;

	/* 
	 * Loop through the registered ENRs to drop temp tables. 
	 */
	while (lc || (lc = list_head(queryEnv->namedRelList)))
	{
		EphemeralNamedRelation enr;

		enr = (EphemeralNamedRelation) lfirst(lc);

		if (enr->md.enrtype != ENR_TSQL_TEMP) {
			lc = lnext(queryEnv->namedRelList, lc);
			if (!lc)
				break;
			else
				continue;
		}

		/* 
		 * performDeletion() will remove the table AND the ENR entry, so no
		 * need to remove the entry afterwards.
		 */

		object.objectId = enr->md.reliddesc;
		performDeletion(&object, DROP_CASCADE, PERFORM_DELETION_INTERNAL | PERFORM_DELETION_QUIETLY);

		/* Reset lc so we can read the head of the list */
		lc = NULL;
	}
}
