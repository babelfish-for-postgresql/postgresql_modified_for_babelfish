/*-------------------------------------------------------------------------
 *
 * Utility routines for babelfish objects
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/bin/pg_dump/dump_babel_utils.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include "catalog/pg_class_d.h"
#include "catalog/pg_proc_d.h"
#include "catalog/pg_type_d.h"
#include "dump_babel_utils.h"
#include "pg_backup_db.h"
#include "pg_dump.h"
#include "pqexpbuffer.h"

static char *
getLanguageName(Archive *fout, Oid langid)
{
	PQExpBuffer query;
	PGresult   *res;
	char	   *lanname;

	query = createPQExpBuffer();
	appendPQExpBuffer(query, "SELECT lanname FROM pg_language WHERE oid = %u", langid);
	res = ExecuteSqlQueryForSingleRow(fout, query->data);
	lanname = pg_strdup(PQgetvalue(res, 0, 0));
	destroyPQExpBuffer(query);
	PQclear(res);

	return lanname;
}

/*
 * isBabelfishDatabase:
 * returns true if current database has "babelfishpg_tsql"
 * extension installed, false otherwise.
 */
static bool
isBabelfishDatabase(Archive *fout)
{
	PGresult *res;
	int		 ntups;

	res = ExecuteSqlQuery(fout, "SELECT extname FROM pg_extension WHERE extname = 'babelfishpg_tsql';", PGRES_TUPLES_OK);
	ntups = PQntuples(res);
	PQclear(res);

	return ntups != 0;
}

/*
 * bbf_selectDumpableCast: Mark a cast as to be dumped or not
 */
void
bbf_selectDumpableCast(CastInfo *cast)
{
	TypeInfo      *sTypeInfo;
	TypeInfo      *tTypeInfo;
	ExtensionInfo *ext = findOwningExtension(cast->dobj.catId);

	/* Skip if cast is not a member of babelfish extension */
	if (ext == NULL || strcmp(ext->dobj.name, "babelfishpg_common") != 0)
		return;

	sTypeInfo = findTypeByOid(cast->castsource);
	tTypeInfo = findTypeByOid(cast->casttarget);

	/*
	 * Do not dump following unused CASTS:
	 * pg_catalog.bool -> sys.bpchar
	 * pg_catalog.bool -> sys.varchar
	 */
	if (sTypeInfo && tTypeInfo &&
			sTypeInfo->dobj.namespace &&
			tTypeInfo->dobj.namespace &&
			strcmp(sTypeInfo->dobj.namespace->dobj.name, "pg_catalog") == 0 &&
			strcmp(tTypeInfo->dobj.namespace->dobj.name, "sys") == 0 &&
			strcmp(sTypeInfo->dobj.name, "bool") == 0 &&
			(strcmp(tTypeInfo->dobj.name, "bpchar") == 0 ||
			 strcmp(tTypeInfo->dobj.name, "varchar") == 0))
		cast->dobj.dump = DUMP_COMPONENT_NONE;
}

/*
 * fixTsqlTableTypeDependency:
 * Fixes following two types of dependency issues between T-SQL
 * table-type and T-SQL MS-TVF/procedure:
 * 1. T-SQL table-type has an INTERNAL dependency upon MS-TVF which
 *    is right thing for drop but creates dependency loop during
 *    pg_dump. Fix this by removing table-type's dependency on MS-TVF.
 * 2. By default function gets dumped before the template table of T-SQL
 *    table type(one of the datatype of function's arguments) which is
 *    because there is no dependency between function and underlying
 *    template table. Ideally function should have a dependency upon table
 *    instead of table-type but it is fine in normal case but becomes
 *    problematic during restore. Fix this by adding function's dependency
 *    on template table.
 */
void
fixTsqlTableTypeDependency(Archive *fout, DumpableObject *dobj, DumpableObject *refdobj, char deptype)
{
	FuncInfo  *funcInfo;
	TypeInfo  *typeInfo;
	TableInfo *tytable;
	char	  *lanname;

	if (!isBabelfishDatabase(fout))
		return;

	if (deptype == 'n' &&
		dobj->objType == DO_FUNC &&
		refdobj->objType == DO_DUMMY_TYPE)
	{
		funcInfo = (FuncInfo *) dobj;
		typeInfo = (TypeInfo *) refdobj;
	}
	else if (deptype == 'i' &&
			dobj->objType == DO_DUMMY_TYPE &&
			refdobj->objType == DO_FUNC)
	{
		funcInfo = (FuncInfo *) refdobj;
		typeInfo = (TypeInfo *) dobj;
	}
	else
		return;

	lanname = getLanguageName(fout, funcInfo->lang);

	/* skip auto-generated array types and non-pltsql functions */
	if (typeInfo->isArray ||
		!OidIsValid(typeInfo->typrelid) ||
		strcmp(lanname, "pltsql") != 0)
	{
		free(lanname);
		return;
	}
	free(lanname);

	tytable = findTableByOid(typeInfo->typrelid);

	if (tytable == NULL)
		return;

	/* First case, so remove INTERNAL dependency between T-SQL table-type and MS-TVF */
	if (deptype == 'i')
		removeObjectDependency(dobj, refdobj->dumpId);
	/* Second case */
	else
		addObjectDependency(dobj, tytable->dobj.dumpId);
}

/*
 * isTsqlTableType:
 * Returns true if given table is a template table for
 * underlying T-SQL table-type, false otherwise.
 */
bool
isTsqlTableType(Archive *fout, const TableInfo *tbinfo)
{
	Oid			pg_type_oid;
	PQExpBuffer query;
	PGresult	*res;
	int			ntups;

	if(!isBabelfishDatabase(fout) || tbinfo->relkind != RELKIND_RELATION)
		return false;

	query = createPQExpBuffer();

	/* get oid of table's row type */
	appendPQExpBuffer(query,
					  "SELECT reltype "
					  "FROM pg_catalog.pg_class "
					  "WHERE relkind = '%c' "
					  "AND oid = '%u'::pg_catalog.oid;",
					  RELKIND_RELATION, tbinfo->dobj.catId.oid);

	res = ExecuteSqlQueryForSingleRow(fout, query->data);
	pg_type_oid = atooid(PQgetvalue(res, 0, PQfnumber(res, "reltype")));

	PQclear(res);
	resetPQExpBuffer(query);

	/* Check if there is a dependency entry in pg_depend from table to it's row type */
	appendPQExpBuffer(query,
					  "SELECT classid "
					  "FROM pg_catalog.pg_depend "
					  "WHERE deptype = 'i' "
					  "AND objid = '%u'::pg_catalog.oid "
					  "AND refobjid = '%u'::pg_catalog.oid "
					  "AND refclassid = 'pg_catalog.pg_type'::pg_catalog.regclass;",
					  tbinfo->dobj.catId.oid, pg_type_oid);

	res = ExecuteSqlQuery(fout, query->data, PGRES_TUPLES_OK);
	ntups = PQntuples(res);

	PQclear(res);
	destroyPQExpBuffer(query);

	return ntups != 0;
}

/*
 * getTsqlTvfType:
 * Returns one of the type of PL/tsql table valued function:
 * 1. PLTSQL_TVFTYPE_NONE : not a PL/tsql table valued function.
 * 2. PLTSQL_TVFTYPE_MSTVF: PL/tsql multi-statement table valued
 *                          function. A function is MS-TVF if it
 *                          returns set (TABLE) and return type
 *                          is composite type.
 * 3. PLTSQL_TVFTYPE_ITVF : PL/tsql inline table valued function.
 *                          A function is ITVF if it returns set
 *                          (TABLE) but return type is not composite
 *                          type.
 */
int
getTsqlTvfType(Archive *fout, const FuncInfo *finfo, char prokind, bool proretset)
{
	TypeInfo *rettype;
	char	 *lanname;

	if (!isBabelfishDatabase(fout) || prokind == PROKIND_PROCEDURE || !proretset)
		return PLTSQL_TVFTYPE_NONE;

	rettype = findTypeByOid(finfo->prorettype);
	lanname = getLanguageName(fout, finfo->lang);

	if (rettype && lanname &&
		strcmp(lanname, "pltsql") == 0)
	{
		free(lanname);

		if (rettype->typtype == TYPTYPE_COMPOSITE)
			return PLTSQL_TVFTYPE_MSTVF;
		else
			return PLTSQL_TVFTYPE_ITVF;
	}

	free(lanname);
	return PLTSQL_TVFTYPE_NONE;
}

/*
 * setOrResetPltsqlFuncRestoreGUCs:
 * sets/resets GUCs required to properly restore
 * PL/tsql functions/procedures depending upon
 * the value of is_set boolean.
 */
void
setOrResetPltsqlFuncRestoreGUCs(Archive *fout, PQExpBuffer q, const FuncInfo *finfo, char prokind, bool proretset, bool is_set)
{
	int pltsql_tvf_type = getTsqlTvfType(fout, finfo, prokind, proretset);

	/* GUCs required for PL/tsql TVFs */
	switch (pltsql_tvf_type)
	{
		case PLTSQL_TVFTYPE_MSTVF:
		{
			if (is_set)
				appendPQExpBufferStr(q,
								 "SET babelfishpg_tsql.restore_tsql_tabletype = TRUE;\n");
			else
				appendPQExpBufferStr(q,
								 "RESET babelfishpg_tsql.restore_tsql_tabletype;\n");
			break;
		}
		case PLTSQL_TVFTYPE_ITVF:
		{
			if (is_set)
				appendPQExpBufferStr(q,
								 "SET babelfishpg_tsql.dump_restore = TRUE;\n");
			else
				appendPQExpBufferStr(q,
								 "RESET babelfishpg_tsql.dump_restore;\n");
			break;
		}
		default:
			break;
	}
}