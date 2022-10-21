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
#include "common/logging.h"
#include "dump_babel_utils.h"
#include "pg_backup_db.h"
#include "pg_dump.h"
#include "pqexpbuffer.h"

char *
getMinOid(Archive *fout)
{
	PGresult *res;
	PQExpBuffer query;
	char *oid;

	query = createPQExpBuffer();

	/*
	 * Oids in the below 5 catalog tables are preserved during dump and restore.
	 * To prevent duplicated object_ids in Babelfish, a new cluster should use
	 * oids greate than the below maximum oid.
	 */
	appendPQExpBuffer(query,
					 "select max(oid) from"
					 "  (select max(oid) oid from pg_extension"
					 "   union"
					 "   select max(oid) oid from pg_authid"
					 "   union"
					 "   select max(oid) oid from pg_enum"
					 "   union"
					 "   select max(oid) oid from pg_class"
					 "   union"
					 "   select max(oid) oid from pg_type"
					 "  ) t"
					 );
	res = ExecuteSqlQueryForSingleRow(fout, query->data);
	oid = pg_strdup(PQgetvalue(res, 0, 0));

	destroyPQExpBuffer(query);
	PQclear(res);

	return oid;
}

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
bool
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
 * T-SQL allows an empty/space-only string as a default constraint of
 * NUMERIC column in CREATE TABLE statement. However, it will eventually
 * throw an error when actual INSERT happens for the default value.
 *
 * To support this behavior, we use a function sys.babelfish_runtime_error(),
 * which raises an error in execution time.
 *
 * However, pg_dump evaluates the runtime error function and replaces it with an
 * error string that causes MVU failure during restore. Hence, we replace the error
 * string by sys.babelfish_runtime_error() again.
 */
void
fixTsqlDefaultExpr(Archive *fout, AttrDefInfo *attrDefInfo)
{
	char *source = attrDefInfo->adef_expr;
	char *runtimeErrFunc = "babelfish_runtime_error";
	char *runtimeErrStr = "'An empty or space-only string cannot be converted into numeric/decimal data type'";
	char *atttypname;

	if (!isBabelfishDatabase(fout) ||
		!strstr(source, runtimeErrStr) ||
		strstr(source, runtimeErrFunc) ||
		attrDefInfo->adnum < 1)
		return;

	atttypname = attrDefInfo->adtable->atttypnames[attrDefInfo->adnum - 1];
	if (!strstr(atttypname, "decimal") && !strstr(atttypname, "numeric"))
		return;

	/* Replace the default expr to runtime error function */
	free(source);
	attrDefInfo->adef_expr = psprintf("(sys.%s(%s::text))::integer", runtimeErrFunc, runtimeErrStr);
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
 * In Babelfish v1.2, we redefined some operators to fix issues.
 * However, we cannot replace those operators using upgrade scripts
 * because customer-defined objects can depend on the operators.
 * This function will do in-place substitutions as a part of pg_dump.
 */
void
fixOprRegProc(Archive *fout,
			  const OprInfo *oprinfo,
			  const char *oprleft,
			  const char *oprright,
			  char **oprregproc)
{
	const char *nsname;
	const char *oprname;

	if (!isBabelfishDatabase(fout) || fout->remoteVersion >= 140000)
		return;

	nsname = oprinfo->dobj.namespace->dobj.name;
	if (strcmp(nsname, "sys") != 0)
		return;

	oprname = oprinfo->dobj.name;
	if (strcmp(oprname, "+") == 0 &&
		strcmp(oprleft, "\"text\"") == 0 &&
		strcmp(oprright, "\"text\"") == 0)
	{
		free(*oprregproc);
		*oprregproc = pg_strdup("\"sys\".\"babelfish_concat_wrapper_outer\"");
	}
	else if (strcmp(oprname, "/") == 0 && strcmp(oprright, "\"sys\".\"fixeddecimal\"") == 0)
	{
		if (strcmp(oprleft, "bigint") == 0)
		{
			free(*oprregproc);
			*oprregproc = pg_strdup("\"sys\".\"int8fixeddecimaldiv_money\"");
		}
		else if (strcmp(oprleft, "integer") == 0)
		{
			free(*oprregproc);
			*oprregproc = pg_strdup("\"sys\".\"int4fixeddecimaldiv_money\"");
		}
		else if (strcmp(oprleft, "smallint") == 0)
		{
			free(*oprregproc);
			*oprregproc = pg_strdup("\"sys\".\"int2fixeddecimaldiv_money\"");
		}
	}
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

void fixAttoptionsBbfOriginalName(Archive *fout, Oid relOid, const TableInfo *tbinfo, int idx)
{
	PGresult *res;
	PQExpBuffer q;
	char *escapedAttname;
	char *attname = tbinfo->attnames[idx];

	if (!isBabelfishDatabase(fout))
		return;

	/* 2*strlen+1 bytes are required for PQescapeString according to the documentation */
	escapedAttname = pg_malloc(2 * strlen(attname) + 1);
	PQescapeString(escapedAttname, attname, strlen(attname));

	q = createPQExpBuffer();

	/*
	 * As attoptions can be a list of options,
	 * we will split options first, make them as an array, find an option starting with 'bbf_original_name',
	 * enclose its value with single quotes, and aggregate all array elements into a single string.
	 */
	appendPQExpBuffer(q,
		"SELECT string_agg( "
		"CASE "
		"WHEN option LIKE 'bbf_original_name=%%' "
		"THEN 'bbf_original_name=' || quote_literal(substring(option, length('bbf_original_name=')+1)) "
		"ELSE option "
		"END, ',')::text as options "
		"FROM ( "
		"SELECT UNNEST(attoptions) as option FROM pg_attribute where attrelid = %d and attname = '%s' "
		") option",
		relOid,
		escapedAttname
		);

	res = ExecuteSqlQueryForSingleRow(fout, q->data);

	free(escapedAttname);
	PQfreemem(tbinfo->attoptions[idx]);

	tbinfo->attoptions[idx] = pg_strdup(PQgetvalue(res, 0, 0));

	destroyPQExpBuffer(q);
	PQclear(res);
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
		default:
			break;
	}
}
