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
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
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
#include "access/relation.h"
#include "access/relscan.h"        /* SysScan related */
#include "access/xact.h"           /* GetCurrentCommandId */
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_statistic.h"
#include "catalog/pg_statistic_ext.h"
#include "catalog/pg_type.h"
#include "catalog/pg_depend.h"
#include "catalog/pg_sequence.h"
#include "catalog/pg_attrdef.h"
#include "catalog/pg_shdepend.h"
#include "catalog/pg_index_d.h"
#include "parser/parser.h"      /* only needed for GUC variables */
#include "storage/smgr.h"
#include "utils/inval.h"
#include "utils/guc.h"
#include "utils/syscache.h"
#include "utils/queryenvironment.h"
#include "utils/rel.h"

pltsql_get_tsql_enr_from_oid_hook_type pltsql_get_tsql_enr_from_oid_hook = NULL;

/*
 * Private state of a query environment.
 */
struct QueryEnvironment
{
	List	   *namedRelList;
	List	   *dropped_namedRelList;
	List 	   *savedCatcacheMessages;
	struct QueryEnvironment *parentEnv;
	MemoryContext	memctx;
};

struct QueryEnvironment topLevelQueryEnvData;
struct QueryEnvironment *topLevelQueryEnv = &topLevelQueryEnvData;
struct QueryEnvironment *currentQueryEnv = NULL;

static void tsql_setup_queryEnv(QueryEnvironment *queryEnv);
static void tsql_cleanup_queryEnv(QueryEnvironment *queryEnv);
static void free_ENR(EphemeralNamedRelation enr);
static bool _ENR_tuple_operation(Relation catalog_rel, HeapTuple tup, ENRTupleOperationType op, bool skip_cache_inval, bool in_enr_rollback);
static void ENRAddUncommittedTupleData(EphemeralNamedRelation enr, Oid catoid, ENRTupleOperationType op, HeapTuple tup, bool in_enr_rollback);
static void ENRDeleteUncommittedTupleData(SubTransactionId subid, EphemeralNamedRelation enr);
static void ENRRollbackUncommittedTuple(QueryEnvironment *queryEnv, ENRUncommittedTuple uncommitted_tup);
static EphemeralNamedRelation find_enr(Form_pg_depend entry);

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
		tsql_setup_queryEnv(queryEnv);
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
	tsql_cleanup_queryEnv(currentQueryEnv);
	pfree(currentQueryEnv);
	MemoryContextSwitchTo(oldcxt);

	currentQueryEnv = tmp;
}

/* Any tsql-specific queryEnv initialization should go here. */
static void tsql_setup_queryEnv(QueryEnvironment *queryEnv)
{
	queryEnv->namedRelList = NIL;
	queryEnv->dropped_namedRelList = NIL;
	queryEnv->savedCatcacheMessages = NIL;
}

/* Any tsql-specific queryEnv cleanup should go here. */
static void tsql_cleanup_queryEnv(QueryEnvironment *queryEnv)
{
	ListCell *lc;

	/* Clean up structures in currentQueryEnv */
	foreach(lc, currentQueryEnv->dropped_namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);
		free_ENR(enr);
		pfree(enr);
	}

	list_free(currentQueryEnv->dropped_namedRelList);
	currentQueryEnv->dropped_namedRelList = NIL;

	list_free(currentQueryEnv->savedCatcacheMessages);
	currentQueryEnv->savedCatcacheMessages = NIL;
}

EphemeralNamedRelationMetadata
get_visible_ENR_metadata(QueryEnvironment *queryEnv, const char *refname)
{
	EphemeralNamedRelation enr;

	Assert(refname != NULL);

	if (queryEnv == NULL)
		return NULL;

	enr = get_ENR(queryEnv, refname, false);
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
	Assert(get_ENR(queryEnv, enr->md.name, false) == NULL);

	if (enr->md.name[0] == '#')
		enr->md.is_bbf_temp_table = true;
	else
		enr->md.is_bbf_temp_table = false;

	if (enr->md.is_bbf_temp_table && GetCurrentSubTransactionId() != InvalidSubTransactionId)
		enr->md.created_subid = GetCurrentSubTransactionId();

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

	match = get_ENR(queryEnv, name, false);
	if (match)
		queryEnv->namedRelList = list_delete(queryEnv->namedRelList, match);
}

/*
 * Return the list of ENRs registered in the current query environment.
 */
List *get_namedRelList()
{
	List *relList = NIL;
	QueryEnvironment *qe = currentQueryEnv;
	while (qe)
	{
		relList = list_concat(relList, qe->namedRelList);
		qe = qe->parentEnv;
	}
	return relList;
}

/*
 * This returns an ENR if there is a name match in the given collection.  It
 * must quietly return NULL if no match is found.
 * 
 * search - true if we want to include parent queryEnvs (such as in 
 * 			babelfish_get_enr_list, object_id).
 * 
 * 			Other such places (like in HeapCreateWithCatalog, SPI)
 * 			allow duplicate ENR names in the top level queryEnv, so 
 * 			it must be false there.
 */
EphemeralNamedRelation
get_ENR(QueryEnvironment *queryEnv, const char *name, bool search)
{
	ListCell   *lc;
	QueryEnvironment *qe = queryEnv;

	Assert(name != NULL);

	if (queryEnv == NULL)
		return NULL;

	while (qe)
	{
		foreach(lc, qe->namedRelList)
		{
			EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

			if (strcmp(enr->md.name, name) == 0)
				return enr;
		}
		if (!search)
			break;
		qe = qe->parentEnv;
	}

	return NULL;
}

/*
 * Same as get_ENR() but just search for relation oid
 */
EphemeralNamedRelation
get_ENR_withoid(QueryEnvironment *queryEnv, Oid id, EphemeralNameRelationType type)
{
	ListCell   *lc;

	if (queryEnv == NULL || !OidIsValid(id))
		return NULL;

	foreach(lc, queryEnv->namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		if (enr->md.reliddesc == id && enr->md.enrtype == type)
			return enr;
	}

	return NULL;
}

/*
 * This is a wrapper function to get_ENR_withoid with the commonly 
 * provided arguments of currentQueryEnv and ENR_TSQL_TEMP.
 */
EphemeralNamedRelation
GetENRTempTableWithOid(Oid id)
{
	return get_ENR_withoid(currentQueryEnv, id, ENR_TSQL_TEMP);
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
bool ENRGetSystableScan(Relation rel, Oid indexId, int nkeys, ScanKey key, List **tuplist, int *tuplist_i, int *tuplist_flags)
{
	QueryEnvironment *queryEnv = currentQueryEnv;
	bool found = false;
	int index = 0;
	Datum v1 = 0, v2 = 0, v3 = 0, v4 = 0;
	Oid pltsql_lang_oid = InvalidOid;
	Oid pltsql_validator_oid = InvalidOid;

	Oid reloid = RelationGetRelid(rel);

	if (sql_dialect != SQL_DIALECT_TSQL)
	{
		/*
		* We cannot return false right away when sql_dialect is not TSQL.
		* There are cases when sql_dialect is temporarily set to PG when
		* executing PG functions such as nextval_internal() in the case of
		* identity sequence.
		*/
		if (reloid != SequenceRelationId)
			return false;

		if (get_func_language_oids_hook)
			get_func_language_oids_hook(&pltsql_lang_oid, &pltsql_validator_oid);

		if (pltsql_lang_oid == InvalidOid)
			return false;
	}

	if (reloid != RelationRelationId &&
		reloid != TypeRelationId &&
		reloid != AttributeRelationId &&
		reloid != ConstraintRelationId &&
		reloid != StatisticRelationId &&
		reloid != StatisticExtRelationId &&
		reloid != DependRelationId &&
		reloid != SharedDependRelationId &&
		reloid != IndexRelationId &&
		reloid != SequenceRelationId &&
		reloid != AttrDefaultRelationId)
		return false;

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
		ListCell   *outerlc;

		foreach(outerlc, queryEnv->namedRelList)
		{
			EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(outerlc);
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
			else if (reloid == DependRelationId)
			{
				/*
				* Search through the entire ENR relation list for everything
				* that has a relation (non-recursive) to this object.
				* If indexId is DependDependerIndexId, we try to mimic
				* SELECT * FROM pg_depend WHERE classid=v1 AND objid=v2 (AND objsubid = v3 if applicable)
				* Otherwise if it is DependReferenceIndexId we try to mimic
				* SELECT * FROM pg_depend WHERE refclassid=v1 AND refobjid=v2 (AND refobjsubid = v3 if applicable)
				* So we cannot return right away if there is a match.
				*/
				ListCell   *lc;
				foreach(lc, enr->md.cattups[ENR_CATTUP_DEPEND]) {
					Form_pg_depend tup = (Form_pg_depend) GETSTRUCT((HeapTuple) lfirst(lc));
					if (indexId == DependDependerIndexId &&
						tup->classid == (Oid)v1 &&
						tup->objid == (Oid)v2 &&
						(nkeys == 2 || tup->objsubid == (int32)v3))
					{
						*tuplist = list_insert_nth(*tuplist, index++, lfirst(lc));
						*tuplist_flags |= SYSSCAN_ENR_NEEDFREE;
						found = true;
					}
					else if (indexId == DependReferenceIndexId &&
						tup->refclassid == (Oid)v1 &&
						tup->refobjid == (Oid)v2 &&
						(nkeys == 2 || tup->refobjsubid == (int32)v3))
					{
						*tuplist = list_insert_nth(*tuplist, index++, lfirst(lc));
						*tuplist_flags |= SYSSCAN_ENR_NEEDFREE;
						found = true;
					}
				}
				*tuplist_i = 0;
			}
			else if (reloid == SharedDependRelationId)
			{
				ListCell   *lc;
				foreach(lc, enr->md.cattups[ENR_CATTUP_SHDEPEND]) {
					Form_pg_shdepend tup = (Form_pg_shdepend) GETSTRUCT((HeapTuple) lfirst(lc));
					if (indexId == SharedDependDependerIndexId &&
						tup->classid == (Oid)v1 &&
						tup->objid == (Oid)v2) {
						*tuplist = enr->md.cattups[ENR_CATTUP_SHDEPEND];
						*tuplist_i = foreach_current_index(lc);
						return true;
					}
					else if (indexId == SharedDependReferenceIndexId &&
							 tup->refclassid == (Oid)v1 &&
							 tup->refobjid == (Oid)v2) {
						*tuplist = enr->md.cattups[ENR_CATTUP_SHDEPEND];
						*tuplist_i = foreach_current_index(lc);
						return true;
					}
				}
			}
			else if (reloid == IndexRelationId)
			{
				ListCell   *lc;
				foreach(lc, enr->md.cattups[ENR_CATTUP_INDEX]) {
					Form_pg_index tup = (Form_pg_index) GETSTRUCT((HeapTuple) lfirst(lc));
					if (indexId == IndexIndrelidIndexId &&
						tup->indrelid == (Oid)v1)
					{
						*tuplist = list_insert_nth(*tuplist, index++, lfirst(lc));
						*tuplist_flags |= SYSSCAN_ENR_NEEDFREE;
						found = true;
					}
					else if (indexId == IndexRelidIndexId &&
							tup->indexrelid == (Oid)v1)
					{
						*tuplist = list_insert_nth(*tuplist, index++, lfirst(lc));
						*tuplist_flags |= SYSSCAN_ENR_NEEDFREE;
						found = true;
					}
				}
				*tuplist_i = 0;
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
			else if (reloid == SequenceRelationId) {
				if (indexId == SequenceRelidIndexId) {
					if (enr->md.reliddesc == (Oid)v1) {
						*tuplist = enr->md.cattups[ENR_CATTUP_SEQUENCE];
						*tuplist_i = 0;
						return true;
					}
				}
			}
			else if (reloid == AttrDefaultRelationId) {
				ListCell *lc;
				foreach(lc, enr->md.cattups[ENR_CATTUP_ATTR_DEF_REL]) {
					Form_pg_attrdef tup = (Form_pg_attrdef) GETSTRUCT((HeapTuple) lfirst(lc));
					if(indexId == AttrDefaultIndexId) {
						/* Callers could pass in nkeys=1 or nkeys=2 */
						if ((nkeys == 1 && tup->adrelid == (Oid)v1) ||
							(nkeys == 2 && tup->adrelid == (Oid)v1 && tup->adnum == (Oid)v2))
						{
							*tuplist = list_insert_nth(*tuplist, index++, lfirst(lc));
							*tuplist_flags |= SYSSCAN_ENR_NEEDFREE;
							found = true;
						}
					}
					else if(indexId == AttrDefaultOidIndexId &&
							tup->oid == (Oid)v1)
					{
						*tuplist = list_insert_nth(*tuplist, index++, lfirst(lc));
						*tuplist_flags |= SYSSCAN_ENR_NEEDFREE;
						found = true;
					}
				}
				*tuplist_i = 0;
			}
		}
		queryEnv = queryEnv->parentEnv;
	}
	return found;
}


/*
 * Add tuple to an ENR. It assumes that an ENR entry has been created with
 * the relation name and relation oid.
 */
bool ENRAddTuple(Relation rel, HeapTuple tup)
{
	return _ENR_tuple_operation(rel, tup, ENR_OP_ADD, false, false);
}

/*
 * Drop tuple of an ENR.
 * We shouldn't assume the origin of the input tuples (i.e. whether it comes
 * from the ENR itself) so we need to search in ENR based on the given tuple.
 */
bool ENRDropTuple(Relation rel, HeapTuple tup)
{
	/*
	 * If we've already dropped it in this transaction but haven't committed, pretend the drop is done. 
	 */
	return _ENR_tuple_operation(rel, tup, ENR_OP_DROP, false, false);
}

/*
 * Update tuple of an ENR.
 */
bool ENRUpdateTuple(Relation rel, HeapTuple tup)
{
	return _ENR_tuple_operation(rel, tup, ENR_OP_UPDATE, false, false);
}

/*
 * Workhorse for add/update/drop tuples in the ENR.
 *
 * Return true if the asked operation is done.
 * Return false if the asked operation is not possible.
 */
static bool _ENR_tuple_operation(Relation catalog_rel, HeapTuple tup, ENRTupleOperationType op, bool skip_cache_inval, bool in_enr_rollback)
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
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
					list_ptr = &enr->md.cattups[ENR_CATTUP_CLASS];
					lc = list_head(enr->md.cattups[ENR_CATTUP_CLASS]);
					ret = true;
				}
				break;
			case DependRelationId:
				{
					Form_pg_depend tf1 = (Form_pg_depend) GETSTRUCT((HeapTuple)tup);
					if ((enr = find_enr(tf1))) {
						ListCell *curlc;
						Form_pg_depend tf2; /* tuple forms*/

						list_ptr = &enr->md.cattups[ENR_CATTUP_DEPEND];
						foreach(curlc, enr->md.cattups[ENR_CATTUP_DEPEND]) {
							tf2 = (Form_pg_depend) GETSTRUCT((HeapTuple)lfirst(curlc));
							if (tf1->classid == tf2->classid &&
								tf1->objid == tf2->objid &&
								tf1->objsubid == tf2->objsubid) {
								lc = curlc;
								break;
							}
						}
						ret = true;
					}
					break;
				}
			case SharedDependRelationId:
				{
					Form_pg_shdepend tf1 = (Form_pg_shdepend) GETSTRUCT((HeapTuple)tup);
					rel_oid = ((Form_pg_shdepend) GETSTRUCT(tup))->objid;
					if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
						ListCell *curlc;
						Form_pg_shdepend tf2; /* tuple forms*/

						list_ptr = &enr->md.cattups[ENR_CATTUP_SHDEPEND];
						foreach(curlc, enr->md.cattups[ENR_CATTUP_SHDEPEND]) {
							tf2 = (Form_pg_shdepend) GETSTRUCT((HeapTuple)lfirst(curlc));
							if (tf1->dbid == tf2->dbid &&
								tf1->classid == tf2->classid &&
								tf1->objid == tf2->objid &&
								tf1->objsubid == tf2->objsubid) {
								lc = curlc;
								break;
							}
						}
						ret = true;
					}
					break;
				}
			case IndexRelationId:
				rel_oid = ((Form_pg_index) GETSTRUCT(tup))->indrelid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
					list_ptr = &enr->md.cattups[ENR_CATTUP_INDEX];
					lc = list_head(enr->md.cattups[ENR_CATTUP_INDEX]);
					ret = true;
				}
				break;
			case TypeRelationId:
				/* Composite type */
				if (((Form_pg_type) GETSTRUCT(tup))->typelem == InvalidOid) {
					rel_oid = ((Form_pg_type) GETSTRUCT(tup))->typrelid;
					if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
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
						if (tmp_enr->md.enrtype == ENR_TSQL_TEMP){
							// inserted & delted are special tmp enr
							type_lc = list_head(tmp_enr->md.cattups[ENR_CATTUP_TYPE]);
							if (type_lc && ((Form_pg_type) GETSTRUCT((HeapTuple)lfirst(type_lc)))->oid
											== ((Form_pg_type) GETSTRUCT(tup))->typelem) {
								enr = tmp_enr;
								break;
							}
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
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
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
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
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
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
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
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
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
			case SequenceRelationId:
				rel_oid = ((Form_pg_sequence) GETSTRUCT(tup))->seqrelid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
					list_ptr = &enr->md.cattups[ENR_CATTUP_SEQUENCE];
					lc = list_head(enr->md.cattups[ENR_CATTUP_SEQUENCE]);
					ret = true;
				}
				break;
			case AttrDefaultRelationId:
				rel_oid = ((Form_pg_attrdef) GETSTRUCT(tup))->adrelid;
				if ((enr = get_ENR_withoid(queryEnv, rel_oid, ENR_TSQL_TEMP))) {
					list_ptr = &enr->md.cattups[ENR_CATTUP_ATTR_DEF_REL];
					lc = list_head(enr->md.cattups[ENR_CATTUP_ATTR_DEF_REL]);
					ret = true;
				}
				break;
			default:
				break;
		}

		/* add/drop/update is possible. Do it now. */
		if (ret)
		{
			/* Tell CommandCounterIncrement() we are about to create some inval messages */
			GetCurrentCommandId(true);

			Assert(queryEnv->memctx);
			oldcxt = MemoryContextSwitchTo(queryEnv->memctx);
			switch (op) {
				case ENR_OP_ADD:
					newtup = heap_copytuple(tup);
					if (enr->md.is_bbf_temp_table && temp_table_xact_support)
						ENRAddUncommittedTupleData(enr, catalog_oid, op, newtup, in_enr_rollback);
					*list_ptr = list_insert_nth(*list_ptr, insert_at, newtup);
					CacheInvalidateENRHeapTuple(catalog_rel, newtup, NULL);
					break;
				case ENR_OP_UPDATE:
					/*
					* Invalidate the tuple before updating / removing it from the List.
					* Consider the case when we remove the tuple and cache invalidation
					* failed, then error handling would try to remove it again but would
					* crash because entry is gone from the List but we could still find it in the syscache.
					* If we failed to drop because we failed to invalidate, then subsequent
					* creation of the same table would fail saying the tuple exists already
					* which is much better than crashing.
					*/
					oldtup = lfirst(lc);
					if (enr->md.is_bbf_temp_table && temp_table_xact_support)
						ENRAddUncommittedTupleData(enr, catalog_oid, op, oldtup, in_enr_rollback);
					CacheInvalidateENRHeapTuple(catalog_rel, oldtup, tup);
					lfirst(lc) = heap_copytuple(tup);
					break;
				case ENR_OP_DROP:
					if (enr->md.is_bbf_temp_table && temp_table_xact_support)
						ENRAddUncommittedTupleData(enr, catalog_oid, op, tup, in_enr_rollback);
					if (!skip_cache_inval)
						CacheInvalidateENRHeapTuple(catalog_rel, tup, NULL);
					tmp = lfirst(lc);
					*list_ptr = list_delete_ptr(*list_ptr, tmp);
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
 * Helper for _ENR_tuple_operation
 */
static EphemeralNamedRelation find_enr(Form_pg_depend entry)
{
	QueryEnvironment *queryEnv = currentQueryEnv;
	Oid catalog_oid = entry->classid;

	ListCell         *curlc;

	while (queryEnv)
	{
		switch (catalog_oid) {
			/*
			* pg_depend entry shows relation/type/constraint depends on a given object.
			* Find the relation from ENR. If found, make sure
			* to register the dependency of the ENR relation to this object.
			*/
			case RelationRelationId:
				return get_ENR_withoid(queryEnv, entry->objid, ENR_TSQL_TEMP);

			case TypeRelationId:
				foreach(curlc, queryEnv->namedRelList) {
					EphemeralNamedRelation tmp_enr;
					ListCell *type_lc;

					tmp_enr = (EphemeralNamedRelation) lfirst(curlc);
					if (tmp_enr->md.enrtype != ENR_TSQL_TEMP)
						continue;

					foreach(type_lc, tmp_enr->md.cattups[ENR_CATTUP_TYPE])
					{
						Form_pg_type tup = ((Form_pg_type)GETSTRUCT((HeapTuple)lfirst(type_lc)));
						if (tup->oid == entry->objid)
							return tmp_enr;
					}
					foreach(type_lc, tmp_enr->md.cattups[ENR_CATTUP_ARRAYTYPE])
					{
						Form_pg_type tup = ((Form_pg_type)GETSTRUCT((HeapTuple)lfirst(type_lc)));
						if (tup->oid == entry->objid)
							return tmp_enr;
					}
				}
				break;

			case ConstraintRelationId:
			case AttrDefaultRelationId:
				return get_ENR_withoid(queryEnv, entry->refobjid, ENR_TSQL_TEMP);

			default:
				break;
		}
		queryEnv = queryEnv->parentEnv;
	}
	return NULL;
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

	if ((enr = GetENRTempTableWithOid(id)) == NULL)
		return;

	oldcxt = MemoryContextSwitchTo(currentQueryEnv->memctx);
	currentQueryEnv->namedRelList = list_delete(currentQueryEnv->namedRelList, enr);

	/* If we are dropping a committed ENR, wait until COMMIT to free it. */
	if (temp_table_xact_support && enr->md.is_bbf_temp_table)
	{
		enr->md.dropped_subid = GetCurrentSubTransactionId();
		currentQueryEnv->dropped_namedRelList = lappend(currentQueryEnv->dropped_namedRelList, enr);
	}
	else
	{
		free_ENR(enr);
		pfree(enr);
	}
	MemoryContextSwitchTo(oldcxt);
}

/*
 * Drop all the temp tables registered as ENR in the given query environment.
 */
void
ENRDropTempTables(QueryEnvironment *queryEnv)
{
	ListCell		*lc = NULL;
	ObjectAddress	object;
	ObjectAddresses	*objects;
	int				nrels = 0,
					maxrels = 0;
	SMgrRelation	*srels = NULL;

	if (!queryEnv)
		return;

	objects = new_object_addresses();

	/*
	 * Loop through the registered ENRs to drop temp tables.
	 */
	foreach(lc, queryEnv->namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);
		Relation rel;
		SMgrRelation srel;

		if (enr->md.enrtype != ENR_TSQL_TEMP)
			continue;

		object.classId = RelationRelationId;
		object.objectSubId = 0;
		object.objectId = enr->md.reliddesc;
		add_exact_object_address(&object, objects);
		/*
		 * Delete the physical storage for the relation.
		 * See: smgrDoPendingDeletes()
		 */
		rel = relation_open(enr->md.reliddesc, AccessExclusiveLock);
		srel = smgropen(rel->rd_locator, rel->rd_backend);

		/* allocate the initial array, or extend it, if needed */
		if (maxrels == 0)
		{
			maxrels = 8;
			srels = palloc(sizeof(SMgrRelation) * maxrels);
		}
		else if (maxrels <= nrels)
		{
			maxrels *= 2;
			srels = repalloc(srels, sizeof(SMgrRelation) * maxrels);
		}

		srels[nrels++] = srel;

		relation_close(rel, NoLock);
	}

	/*
	 * The below call to performMultpleDeletions() only registers the 
	 * underlying files for deletion at the end of transaction, but they
	 * need to be deleted now since we are exiting the current scope. We
	 * still need to run the function though, to make sure that all of the
	 * dependencies are properly cleaned up.
	 */
	if (nrels > 0)
	{
		smgrdounlinkall(srels, nrels, false);

		for (int i = 0; i < nrels; i++)
			smgrclose(srels[i]);

		pfree(srels);
	}

	/*
	 * performMultipleDeletions() will remove the table AND the ENR entry,
	 * so no need to remove the entry afterwards. It also takes care of
	 * proper object drop order, to prevent dependency issues.
	 */
	performMultipleDeletions(objects, DROP_CASCADE, PERFORM_DELETION_INTERNAL | PERFORM_DELETION_QUIETLY);
	free_object_addresses(objects);
}

/*
 * Drop all records of the relid from catalog_relation.
 * ie: delete * from catalog_relation where *relid=<relid>
 */
void ENRDropCatalogEntry(Relation catalog_relation, Oid relid)
{
	QueryEnvironment	*queryEnv = currentQueryEnv;
	bool ret = false;
	Oid catalog_oid;
	List	**list_ptr = NULL;
	EphemeralNamedRelation enr;

	catalog_oid = RelationGetRelid(catalog_relation);
	while (queryEnv && !ret)
	{
		switch (catalog_oid) {
			case AttributeRelationId:
				if ((enr = get_ENR_withoid(queryEnv, relid, ENR_TSQL_TEMP))) {
					list_ptr = &enr->md.cattups[ENR_CATTUP_ATTRIBUTE];
					ret = true;
				}
				break;
			default:
				ereport(ERROR, (errmsg("Unreachable codepath")));
		}

		if (ret) {
			HeapTuple htup;
			MemoryContext oldcxt;

			Assert(queryEnv->memctx);
			oldcxt = MemoryContextSwitchTo(queryEnv->memctx);

			while (*list_ptr)
			{
				htup = list_nth(*list_ptr, 0);
				*list_ptr = list_delete_ptr(*list_ptr, htup);

				if (temp_table_xact_support)
					ENRAddUncommittedTupleData(enr, catalog_oid, ENR_OP_DROP, htup, false);

				CacheInvalidateHeapTuple(catalog_relation, htup, NULL);
				heap_freetuple(htup); // heap_copytuple was called during ADD
			}

			MemoryContextSwitchTo(oldcxt);
		}

		queryEnv = queryEnv->parentEnv;
	}
}

/* Loop through structures in the ENR and make sure to free anything that needs to be freed. */
static void free_ENR(EphemeralNamedRelation enr)
{
	for (int i = 0; i < ENR_CATTUP_END; i++)
	{
		List *uncommitted_cattups = enr->md.uncommitted_cattups[i];
		List *cattups = enr->md.cattups[i];
		ListCell *lc2, *lc3;

		foreach(lc2, uncommitted_cattups)
		{
			ENRUncommittedTuple uncommitted_tup = (ENRUncommittedTuple) lfirst(lc2);

			heap_freetuple(uncommitted_tup->tup);
		}

		foreach(lc3, cattups)
		{
			HeapTuple tup = (HeapTuple) lfirst(lc3);

			heap_freetuple(tup);
		}
	}

	pfree(enr->md.name);
}

/*
 * ENRCommitChanges
 *
 * 1. Free uncommitted tuple data from each ENR, then mark it as committed.
 * 2. Finish freeing ENRs that were dropped in this transaction.
 */
void
ENRCommitChanges(QueryEnvironment *queryEnv)
{
	ListCell 	*lc = NULL;
	MemoryContext oldcxt;

	if (!queryEnv)
		return;

	oldcxt = MemoryContextSwitchTo(queryEnv->memctx);

	foreach(lc, queryEnv->namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		if (enr->md.enrtype != ENR_TSQL_TEMP || !enr->md.is_bbf_temp_table)
			continue;

		ENRDeleteUncommittedTupleData(InvalidSubTransactionId, enr);
		enr->md.is_committed = true;
	}

	lc = NULL;

	foreach(lc, queryEnv->dropped_namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		free_ENR(enr);
		pfree(enr);
	}

	list_free(queryEnv->dropped_namedRelList);
	queryEnv->dropped_namedRelList = NIL;

	MemoryContextSwitchTo(oldcxt);
}


/*
 * ENRRollbackChanges
 * 
 * NB: This will also be called when an error occurs for transaction rollback. 
 * 1. Move any ENRs that were dropped back into the main ENR list.
 * 2. Iterate through the ENR list and for each ENR, go through uncommitted tuples
 *    and perform the opposite operation to restore it.
 * 3. Finally, clean up the uncommitted tuple list and perform all the necessary deletions
 *    last to avoid potential for any dependency issues.
 */
void
ENRRollbackChanges(QueryEnvironment *queryEnv)
{
	ListCell 	*lc;
	List *enrs_to_drop = NIL;
	MemoryContext oldcxt;

	if (!queryEnv)
		return;

	oldcxt = MemoryContextSwitchTo(queryEnv->memctx);

	/* Add back any ENRs that must be restored. */
	foreach (lc, queryEnv->dropped_namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		Assert(enr->md.enrtype == ENR_TSQL_TEMP);
		Assert(enr->md.is_bbf_temp_table);

		queryEnv->namedRelList = lappend(queryEnv->namedRelList, enr);	
	}
	list_free(queryEnv->dropped_namedRelList);	
	queryEnv->dropped_namedRelList = NIL;

	/*
	 * Loop through the registered ENRs to process each.
	 */
	foreach(lc, queryEnv->namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		if (enr->md.enrtype != ENR_TSQL_TEMP || !enr->md.is_bbf_temp_table)
			continue;

		if (!enr->md.is_committed)
		{
			enrs_to_drop = lappend(enrs_to_drop, enr);
			continue;
		}

		for (int i = 0; i < ENR_CATTUP_END; i++)
		{
			List *uncommitted_cattups = enr->md.uncommitted_cattups[i];
			ListCell *lc2;

			foreach(lc2, uncommitted_cattups)
			{
				ENRUncommittedTuple uncommitted_tup = (ENRUncommittedTuple) lfirst(lc2);

				ENRRollbackUncommittedTuple(queryEnv, uncommitted_tup);
			}
		}

		ENRDeleteUncommittedTupleData(InvalidSubTransactionId, enr);
	}

	/* Finally, clean up any ENRs that must be deleted. */
	foreach(lc, enrs_to_drop)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);
		queryEnv->namedRelList = list_delete(queryEnv->namedRelList, enr);
		free_ENR(enr);
		pfree(enr);
	}
	MemoryContextSwitchTo(oldcxt);
}

/* This is used when rolling back a subtransaction. */
/* It is similar to ENRRollback */
void ENRRollbackSubtransaction(SubTransactionId subid, QueryEnvironment *queryEnv)
{
	ListCell 	*lc;
	List *enrs_to_drop = NIL;
	MemoryContext oldcxt;

	if (!queryEnv)
		return;

	oldcxt = MemoryContextSwitchTo(queryEnv->memctx);

	/* Add back any ENRs that must be restored. */
	foreach (lc, queryEnv->dropped_namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		Assert(enr->md.enrtype == ENR_TSQL_TEMP);
		Assert(enr->md.is_bbf_temp_table);

		/* If this was dropped in the current subtransaction, then we must restore it. */
		if (enr->md.dropped_subid != InvalidSubTransactionId && enr->md.dropped_subid >= subid) // 4
		{
			queryEnv->namedRelList = lappend(queryEnv->namedRelList, enr);		
			queryEnv->dropped_namedRelList = foreach_delete_current(queryEnv->dropped_namedRelList, lc);
			enr->md.dropped_subid = InvalidSubTransactionId;
		}
	}

	/*
	 * Loop through the registered ENRs to process each.
	 */
	foreach(lc, queryEnv->namedRelList)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		if (enr->md.enrtype != ENR_TSQL_TEMP || !enr->md.is_bbf_temp_table)
			continue;

		if (!enr->md.is_committed && enr->md.created_subid >= subid)
		{
			enrs_to_drop = lappend(enrs_to_drop, enr);
			continue;
		}

		for (int i = 0; i < ENR_CATTUP_END; i++)
		{
			List *uncommitted_cattups = enr->md.uncommitted_cattups[i];
			ListCell *lc2;

			foreach(lc2, uncommitted_cattups)
			{
				ENRUncommittedTuple uncommitted_tup = (ENRUncommittedTuple) lfirst(lc2);

				if (uncommitted_tup->subid < subid)
					continue;

				ENRRollbackUncommittedTuple(queryEnv, uncommitted_tup);
			}
		}

		ENRDeleteUncommittedTupleData(subid, enr);
	}

	/* Finally, clean up any ENRs that must be deleted. */
	foreach(lc, enrs_to_drop)
	{
		EphemeralNamedRelation enr = (EphemeralNamedRelation) lfirst(lc);

		queryEnv->namedRelList = list_delete(queryEnv->namedRelList, enr);
		pfree(enr->md.name);
		pfree(enr);
	}
	MemoryContextSwitchTo(oldcxt);
}

/*
 * Store uncommitted tuple metadata in ENR.
 */
static void
ENRAddUncommittedTupleData(EphemeralNamedRelation enr, Oid catoid, ENRTupleOperationType op, HeapTuple tup, bool in_enr_rollback)
{
	ENRUncommittedTuple uncommitted_tup;
	List **list_ptr = NULL;
	
	if (in_enr_rollback)
		return;
	
	uncommitted_tup = (ENRUncommittedTuple) palloc0(sizeof(ENRUncommittedTupleData));
	uncommitted_tup->catalog_oid = catoid;
	uncommitted_tup->optype = op;
	uncommitted_tup->tup = heap_copytuple(tup);
	uncommitted_tup->subid = GetCurrentSubTransactionId();

	switch (catoid)
	{
		case RelationRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_CLASS];
			break;
		case DependRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_DEPEND];
			break;
		case SharedDependRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_SHDEPEND];
			break;
		case IndexRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_INDEX];
			break;
		case TypeRelationId:
			/* Composite type */
			if (((Form_pg_type) GETSTRUCT(tup))->typelem == InvalidOid) {
				list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_TYPE];
				break;
			/* Array type */
			} else {
				list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_ARRAYTYPE];
				break;
			}
		case AttributeRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_ATTRIBUTE];
			break;
		case ConstraintRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_CONSTRAINT];
			break;
		case StatisticRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_STATISTIC];
			break;
		case StatisticExtRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_STATISTIC_EXT];
			break;
		case SequenceRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_SEQUENCE];
			break;
		case AttrDefaultRelationId:
			list_ptr = &enr->md.uncommitted_cattups[ENR_CATTUP_ATTR_DEF_REL];
			break;
		default:
			/* Shouldn't reach here */
			elog(ERROR, "Did not find matching ENR catalog entry for catoid %d", catoid);
			break;
	}

	/*
	 * lcons here takes the length of the list, so it is less efficient than lappend. 
	 * However, we want the uncommitted_tup order to behave more like a stack to 
	 * process ROLLBACK in the right order of operations. 
	 */
	*list_ptr = lcons(uncommitted_tup, *list_ptr);
}

/*
 * Clean up all uncommitted tuple data from this ENR.
 * 
 * This is called on COMMIT, to wipe unnecessary uncommitted tuple data away
 * and on ROLLBACK, once the changes have been rolled back. 
 */
static void
ENRDeleteUncommittedTupleData(SubTransactionId subid, EphemeralNamedRelation enr)
{
	for (int i = 0; i < ENR_CATTUP_END; i++)
	{
		ListCell *lc;

		foreach(lc, enr->md.uncommitted_cattups[i])
		{
			ENRUncommittedTuple uncommitted_tup = (ENRUncommittedTuple) lfirst(lc);

			if (subid != InvalidSubTransactionId && uncommitted_tup->subid < subid)
				continue;

			heap_freetuple(uncommitted_tup->tup);
			pfree(uncommitted_tup);

			enr->md.uncommitted_cattups[i] = foreach_delete_current(enr->md.uncommitted_cattups[i], lc);
		}
		if (subid == InvalidSubTransactionId)
		{
			list_free(enr->md.uncommitted_cattups[i]);
			enr->md.uncommitted_cattups[i] = NIL;
		}
	}
}

/*
 * Helper function - finish the ROLLBACK processing for a single uncommitted_tup entry.
 */
static void
ENRRollbackUncommittedTuple(QueryEnvironment *queryEnv, ENRUncommittedTuple uncommitted_tup)
{
	Relation rel;
	bool skip_cache_inval = false;

	if (!OidIsValid(uncommitted_tup->catalog_oid) || !HeapTupleIsValid(uncommitted_tup->tup))
	{
		elog(WARNING, "Invalid temp table entries were found during ROLLBACK");
		return;
	}

	if (uncommitted_tup->catalog_oid == IndexRelationId && uncommitted_tup->optype == ENR_OP_ADD)
	{
		/*
		* We skip invalidating IndexRelationId on drop (ie committed table, index created in transaction) 
		* because it will be taken care of when the index itself is dropped - otherwise we risk
		* throwing an error because the entry is already wiped away.
		*/
		
		Form_pg_index idx_form = (Form_pg_index) GETSTRUCT(uncommitted_tup->tup);
		if (get_ENR_withoid(queryEnv, idx_form->indrelid, ENR_TSQL_TEMP))
		{
			skip_cache_inval = true;
		}
	}

	rel = relation_open(uncommitted_tup->catalog_oid, RowExclusiveLock);

	switch(uncommitted_tup->optype)
	{
		/* Peform the opposite operation as the saved optype. */
		case ENR_OP_ADD:
			_ENR_tuple_operation(rel, uncommitted_tup->tup, ENR_OP_DROP, skip_cache_inval, true);
			break;
		case ENR_OP_UPDATE:
			_ENR_tuple_operation(rel, uncommitted_tup->tup, ENR_OP_UPDATE, skip_cache_inval, true);
			break;
		case ENR_OP_DROP:
			_ENR_tuple_operation(rel, uncommitted_tup->tup, ENR_OP_ADD, skip_cache_inval, true);
			break;
	}
	relation_close(rel, RowExclusiveLock);
}

/* This only stores catcache inval messages meant for ENR tables in the current transaction. */
void SaveCatcacheMessage(int cacheId,
							 uint32 hashValue,
							 Oid dbId)
{
	SharedInvalCatcacheMsg *msg = (SharedInvalCatcacheMsg *) palloc0(sizeof(SharedInvalCatcacheMsg));
	msg->id = cacheId;
	msg->dbId = dbId;
	msg->hashValue = hashValue;

	currentQueryEnv->savedCatcacheMessages = lappend(currentQueryEnv->savedCatcacheMessages, msg);
}

/* Clear any saved catcache messages at end of xact. */
void ClearSavedCatcacheMessages()
{
	if (!currentQueryEnv || !currentQueryEnv->savedCatcacheMessages)
		return;

	list_free_deep(currentQueryEnv->savedCatcacheMessages);
	currentQueryEnv->savedCatcacheMessages = NIL;
}

/*
 * SIMessageIsForTempTable
 * 
 * Determine whether the msg sent is for a temp table. 
 * TSQL style temp tables do not need to add messages to the
 * SI queue, as catalog changes are all session-local.
 * 
 * See LocalExecuteInvalidationMessage
 */
bool SIMessageIsForTempTable(const SharedInvalidationMessage *msg)
{
	if (sql_dialect != SQL_DIALECT_TSQL || temp_oid_buffer_size == 0)
		return false;

	if (msg->id >= 0)
	{
		ListCell *lc;
		if (!currentQueryEnv)
			return false;
		foreach(lc, currentQueryEnv->savedCatcacheMessages)
		{
			SharedInvalCatcacheMsg *saved_msg = (SharedInvalCatcacheMsg *) lfirst(lc);
			if (saved_msg->dbId == msg->cc.dbId
			&& saved_msg->hashValue == msg->cc.hashValue
			&& saved_msg->id == msg->cc.id)
				return true;
		}
		return false;
	}
	else if (msg->id == SHAREDINVALCATALOG_ID)
	{
		return false;
	}
	else if (msg->id == SHAREDINVALRELCACHE_ID)
	{
		/* This is set in AddRelcacheInvalidationMessage. */
		return msg->rc.local_only;
	}
	else if (msg->id == SHAREDINVALSMGR_ID)
	{
		return false;
	}
	else if (msg->id == SHAREDINVALRELMAP_ID)
	{
		return false;
	}
	else if (msg->id == SHAREDINVALSNAPSHOT_ID)
	{
		return false;
	}
	else
		elog(ERROR, "unrecognized SI message ID: %d", msg->id);
}

/* Simple wrapper for Table Variable checks */
bool IsTsqlTableVariable(Relation relation)
{
	return sql_dialect == SQL_DIALECT_TSQL 
		&& relation
		&& relation->rd_rel->relpersistence == RELPERSISTENCE_TEMP 
		&& relation->rd_rel->relname.data 
		&& strlen(relation->rd_rel->relname.data) >= 1 
		&& relation->rd_rel->relname.data[0] == '@';
}

/* Simple wrapper for Temp Table checks */
bool IsTsqlTempTable(char relpersistence)
{
	return sql_dialect == SQL_DIALECT_TSQL 
		&& relpersistence == RELPERSISTENCE_TEMP;
}

/* 
 * Simple check for whether to use temp OID buffer.
 */
bool UseTempOidBuffer()
{
	return sql_dialect == SQL_DIALECT_TSQL 
		&& GetNewTempOidWithIndex_hook 
		&& temp_oid_buffer_size > 0;
}

/* Simple check for whether to use temp OID buffer given an existing OID. */
bool UseTempOidBufferForOid(Oid relId)
{
	return UseTempOidBuffer()
		&& GetENRTempTableWithOid(relId);
}

bool has_existing_enr_relations()
{
	QueryEnvironment *queryEnv = currentQueryEnv;

	while (queryEnv)
	{
		if (queryEnv->namedRelList != NIL)
			return true;

		queryEnv = queryEnv->parentEnv;
	}

	return false;
}