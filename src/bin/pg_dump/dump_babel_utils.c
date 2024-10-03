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
#include "fe_utils/string_utils.h"
#include "pg_backup_archiver.h"
#include "pg_backup_db.h"
#include "pg_backup_utils.h"
#include "pg_backup.h"
#include "pg_dump.h"
#include "pqexpbuffer.h"

/*
 * Macro for producing quoted, schema-qualified name of a dumpable object.
 */
#define fmtQualifiedDumpable(obj) \
	fmtQualifiedId((obj)->dobj.namespace->dobj.name, \
				   (obj)->dobj.name)

static const CatalogId nilCatalogId = {0, 0};
static char *escaped_bbf_db_name = NULL;
static int bbf_db_id = 0;
static SimpleOidList catalog_table_include_oids = {NULL, NULL};
static char *babel_init_user = NULL;
static Oid pltsql_langid = InvalidOid;

static char *getMinOid(Archive *fout);
static void addFromClauseForLogicalDatabaseDump(PQExpBuffer buf, TableInfo *tbinfo);
static void addFromClauseForPhysicalDatabaseDump(PQExpBuffer buf, TableInfo *tbinfo);
static int getMbstrlen(const char *mbstr,Archive *fout);
static bool is_ms_shipped(DumpableObject *dobj, Archive *fout);
static bool hasSqlvariantColumn(TableInfo *tbinfo);

/* enum to check if database to be dumped is a Babelfish Database */
typedef enum {
	NONE, OFF, ON
} babelfish_status;

static babelfish_status bbf_status = NONE;


static char *
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

static bool
isPltsqlLanguageOid(Archive *fout, Oid langid)
{
	if (!OidIsValid(pltsql_langid))
	{
		PGresult   *res;

		res = ExecuteSqlQueryForSingleRow(fout, "SELECT oid FROM pg_language WHERE lanname = 'pltsql'");
		pltsql_langid = atoi(PQgetvalue(res, 0, 0));
		PQclear(res);
	}

	return OidIsValid(langid) && (pltsql_langid == langid);
}

/*
 * isBabelfishDatabase:
 * returns true if current database has "babelfishpg_tsql"
 * extension installed, false otherwise.
 */
bool
isBabelfishDatabase(Archive *fout)
{
	if(bbf_status == NONE)
	{
		PGresult *res;
		int		 ntups;
		res = ExecuteSqlQuery(fout, "SELECT extname FROM pg_extension WHERE extname = 'babelfishpg_tsql';", PGRES_TUPLES_OK);
		ntups = PQntuples(res);
		if (ntups != 0)
			bbf_status = ON;
		else
			bbf_status = OFF;
		PQclear(res);
	}
	return (bbf_status == ON);
}

/*
 * is_ms_shipped
 * Returns true if the given object is a system object
 * i.e. object created by babelfish extensions, false otherwise.
 */
static bool
is_ms_shipped(DumpableObject *dobj, Archive *fout)
{
	PQExpBuffer	qry;
	PGresult	*res;
	bool    	ismsshipped = false;

	/* Directly query sys.OBJECTPROPERTY function to know whether it is a system object or not. */
	qry = createPQExpBuffer();
	appendPQExpBuffer(qry, "SELECT sys.OBJECTPROPERTY(%u, 'ismsshipped');\n", dobj->catId.oid);
	res = ExecuteSqlQueryForSingleRow(fout, qry->data);
	if (!PQgetisnull(res, 0, 0))
		ismsshipped = atoi(PQgetvalue(res, 0, 0)) == 1 ? true : false;

	destroyPQExpBuffer(qry);
	PQclear(res);
	return ismsshipped;
}

/*
 * isBabelfishConfigTable:
 * Returns true if given table is a configuration table (for which catalog
 * table data needs to be dumped), false otherwise.
 */
bool
isBabelfishConfigTable(Archive *fout, TableInfo *tbinfo)
{
	if (!isBabelfishDatabase(fout))
		return false;
	/* 
	 * We don't want to dump babelfish_authid_login_ext, babelfish_domain_mapping
	 * and babelfish_server_options in case of logical database dump.
	 */
	if (tbinfo == NULL || tbinfo->relkind != RELKIND_RELATION ||
		(tbinfo->dobj.namespace &&
		strcmp(tbinfo->dobj.namespace->dobj.name, "sys") == 0 &&
		(bbf_db_name != NULL && 
			(strcmp(tbinfo->dobj.name, "babelfish_authid_login_ext") == 0 ||
				strcmp(tbinfo->dobj.name, "babelfish_server_options") == 0 ||
				strcmp(tbinfo->dobj.name, "babelfish_domain_mapping") == 0))))
			return false;

	if (catalog_table_include_oids.head != NULL &&
		simple_oid_list_member(&catalog_table_include_oids, tbinfo->dobj.catId.oid))
		return true;

	return false;
}

/*
 * dumpBabelGUCs:
 * Dumps Babelfish specific GUC settings if current
 * database is a Babelfish database.
 */
void
dumpBabelGUCs(Archive *fout)
{
	char		*oid;
	PQExpBuffer	qry;

	if (!isBabelfishDatabase(fout))
		return;

	qry = createPQExpBuffer();
	appendPQExpBufferStr(qry, "SET babelfishpg_tsql.dump_restore = TRUE;\n");
	if (fout->dopt->binary_upgrade)
	{
		oid = getMinOid(fout);
		appendPQExpBuffer(qry, "SET babelfishpg_tsql.dump_restore_min_oid = %s;\n", oid);
		free(oid);
	}

	/*
	 * Disable triggers for data-only dump.
	 * Although pg_restore provides an option for this (--disable-triggers)
	 * but this option needs superuser privileges. So we will use this
	 * session_replication_role session GUC to temporarily disable the triggers
	 * for the data-only dump so as to allow non-superuser to perform the restore.
	 */
	if(!fout->dopt->binary_upgrade && fout->dopt->dataOnly)
		appendPQExpBufferStr(qry, "SET session_replication_role = replica;\n");

	ArchiveEntry(fout, nilCatalogId, createDumpId(),
				 ARCHIVE_OPTS(.tag = "BABELFISHGUCS",
							  .description = "BABELFISHGUCS",
							  .section = SECTION_PRE_DATA,
							  .createStmt = qry->data));

	destroyPQExpBuffer(qry);
}

/*
 * dumpBabelRestoreChecks:
 * Dumps Babelfish specific pre-checks which get executed at the
 * beginning of restore to validate if restore can be performed
 * or not.
 */
void
dumpBabelRestoreChecks(Archive *fout)
{
	PGresult	*res;
	int     	source_server_version_num;
	char		*source_migration_mode;
	PQExpBuffer	qry;
	ArchiveFormat format = ((ArchiveHandle *) fout)->format;

	/* Skip if not Babelfish database or binary upgrade */
	if (!isBabelfishDatabase(fout) || fout->dopt->binary_upgrade)
		return;

	/*
	 * Cross version Babelfish dump/restore is not yet supported so
	 * store the current server's version in the below procedure and
	 * add logic to fail the restore if the target server version
	 * differs from source server version.
	 */
	qry = createPQExpBuffer();
	res = ExecuteSqlQueryForSingleRow(fout, "SELECT setting::INT from pg_settings WHERE name = 'server_version_num';");
	source_server_version_num = atoi(PQgetvalue(res, 0, 0));

	/*
	 * Temporarily enable ON_ERROR_STOP so that whole restore script
	 * execution fails if the following do block raises an error.
	 * Note that it can only be used in plain text dump (archNull).
	 */
	if (format == archNull)
		appendPQExpBufferStr(qry, "\\set ON_ERROR_STOP on\n\n");
	appendPQExpBuffer(qry,
					  "DO $$"
					  "\nDECLARE"
					  "\n    target_server_version_num INT;"
					  "\nBEGIN"
					  "\n    SELECT INTO target_server_version_num setting::INT from pg_settings"
					  "\n        WHERE name = 'server_version_num';"
					  "\n    IF target_server_version_num != %d THEN"
					  "\n        RAISE 'Dump and restore across different Postgres versions is not yet supported.';"
					  "\n    ELSIF target_server_version_num < 150005 THEN"
					  "\n        RAISE 'Target Postgres version must be 15.5 or higher for Babelfish restore.';"
					  "\n    END IF;"
					  "\nEND$$;\n\n"
					  , source_server_version_num);
	PQclear(res);

	/*
	 * Similar to the above, cross migration mode Babelfish dump/restore
	 * is also not yet supported so store the current server's migration mode
	 * in the below procedure and add logic to fail the restore if the target
	 * server's migration mode differs from source server migration mode.
	 */
	res =  ExecuteSqlQueryForSingleRow(fout, "SHOW babelfishpg_tsql.migration_mode");
	source_migration_mode = pstrdup(PQgetvalue(res, 0, 0));
	appendPQExpBuffer(qry, "DO $$"
					  "\nDECLARE"
					  "\n    target_migration_mode VARCHAR;"
					  "\nBEGIN"
					  "\n    SELECT INTO target_migration_mode setting from pg_settings"
					  "\n        WHERE name = 'babelfishpg_tsql.migration_mode';"
					  "\n    IF target_migration_mode::VARCHAR != '%s' THEN"
					  "\n        RAISE 'Dump and restore across different migration modes is not yet supported.';"
					  "\n    END IF;"
					  "\nEND$$;\n\n"
					  , source_migration_mode);
	if (format == archNull)
		appendPQExpBufferStr(qry, "\\set ON_ERROR_STOP off\n");
	PQclear(res);

	ArchiveEntry(fout, nilCatalogId, createDumpId(),
				 ARCHIVE_OPTS(.tag = "BABELFISHCHECKS",
							  .description = "BABELFISHCHECKS",
							  .section = SECTION_PRE_DATA,
							  .createStmt = qry->data));
	destroyPQExpBuffer(qry);
	pfree(source_migration_mode);
}

/*
 * bbf_selectDumpableObject:
 *		Mark a generic dumpable object as to be dumped or not
 */
void
bbf_selectDumpableObject(DumpableObject *dobj, Archive *fout)
{
	if (!isBabelfishDatabase(fout))
		return;

	switch (dobj->objType)
	{
		case DO_CAST:
			{
				CastInfo    	*cast = (CastInfo *) dobj;
				TypeInfo    	*sTypeInfo;
				TypeInfo    	*tTypeInfo;
				ExtensionInfo	*ext = findOwningExtension(cast->dobj.catId);

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
			break;
		case DO_TABLE:
			{
				TableInfo *tbinfo = (TableInfo *) dobj;

				if (fout->dopt->binary_upgrade)
					return;

				switch (tbinfo->relkind)
				{
					case RELKIND_VIEW:
					{
						/* Return early if the view is already marked not to be dumped */
						if (tbinfo->dobj.dump == DUMP_COMPONENT_NONE)
							return;

						/*
						 * There is special case with sysdatabases view,
						 * we will not dump this view only when it's in default
						 * databases (master/msdb/tempdb), otherwise we
						 * will always dump it.
						 */
						if (tbinfo->dobj.namespace &&
							(strcmp(tbinfo->dobj.namespace->dobj.name, "master_dbo") == 0 ||
							strcmp(tbinfo->dobj.namespace->dobj.name, "msdb_dbo") == 0 ||
							strcmp(tbinfo->dobj.namespace->dobj.name, "tempdb_dbo") == 0) &&
							strcmp(tbinfo->dobj.name, "sysdatabases") == 0)
						{
							tbinfo->dobj.dump = DUMP_COMPONENT_NONE;
							break;
						}

						/* Just skip if it's a system view */
						if (is_ms_shipped(dobj, fout))
							tbinfo->dobj.dump = DUMP_COMPONENT_NONE;
					}
					break;
					case RELKIND_SEQUENCE:
					{
						if (dobj->namespace &&
							strcmp(dobj->namespace->dobj.name, "sys") == 0 &&
							strcmp(dobj->name, "babelfish_db_seq") == 0)
							dobj->dump &= ~DUMP_COMPONENT_ACL;
					}
					break;
					default:
						{
							/*
							 * Mark Babelfish catalog table data to be dumped if not in
							 * binary-upgrade mode. This is needed since babelfish extensions
							 * are not marked to be dumped so catalog table data explicitly
							 * need to be marked as dumpable.
							 */
							if (isBabelfishConfigTable(fout, tbinfo) && !fout->dopt->dataOnly)
							{
								tbinfo->dobj.dump |= DUMP_COMPONENT_DATA;
								/* also prepare the dumpable object upfront */
								makeTableDataInfo(fout->dopt, tbinfo);
							}
						}
				}
			}
			break;
		case DO_NAMESPACE:
			{
				NamespaceInfo *nsinfo = (NamespaceInfo *) dobj;

				/* Return early if it is binary upgrade or the schema is already marked not to be dumped */
				if (fout->dopt->binary_upgrade || nsinfo->dobj.dump == DUMP_COMPONENT_NONE)
					return;

				/*
				 * Do not dump the definition of default babelfish schemas but
				 * their contained objects will be dumped.
				 */
				if (strcmp(nsinfo->dobj.name, "master_dbo") == 0 ||
					strcmp(nsinfo->dobj.name, "master_guest") == 0 ||
					strcmp(nsinfo->dobj.name, "msdb_dbo") == 0 ||
					strcmp(nsinfo->dobj.name, "msdb_guest") == 0 ||
					strcmp(nsinfo->dobj.name, "tempdb_dbo") == 0 ||
					strcmp(nsinfo->dobj.name, "tempdb_guest") == 0)
					nsinfo->dobj.dump &= ~DUMP_COMPONENT_DEFINITION;

				/*
				 * Do not dump any components of the schemas which get created as
				 * part of CREATE EXTENSION babelfish... command.
				 */
				if (strcmp(nsinfo->dobj.name, "babelfishpg_telemetry") == 0)
					nsinfo->dobj.dump = DUMP_COMPONENT_NONE;
			}
			break;
		case DO_EXTENSION:
			{
				ExtensionInfo *extinfo = (ExtensionInfo *) dobj;

				/* Return early if it is binary upgrade or the extension is already marked not to be dumped */
				if (fout->dopt->binary_upgrade || extinfo->dobj.dump == DUMP_COMPONENT_NONE)
					return;

				if (strncmp(extinfo->dobj.name, "babelfishpg", 11) == 0)
					extinfo->dobj.dump = extinfo->dobj.dump_contains = DUMP_COMPONENT_NONE;
			}
			break;
		case DO_FUNC:
			{
				FuncInfo *finfo = (FuncInfo *) dobj;

				/* Return early if it is binary upgrade or the function is already marked not to be dumped */
				if (fout->dopt->binary_upgrade || finfo->dobj.dump == DUMP_COMPONENT_NONE)
					return;

				/* Just skip if it's a system function/procedure */
				if (is_ms_shipped(dobj, fout))
					finfo->dobj.dump = DUMP_COMPONENT_NONE;
			}
			break;
		case DO_CONSTRAINT:
			{
				ConstraintInfo *constrinfo = (ConstraintInfo *) dobj;

				/*
				 * Do not dump UNIQUE/PRIMARY KEY constraint. We will dump the underlying
				 * index and create the constraint using that index instead.
				 * This is needed since in babelfish, a UNIQUE/PRIMARY KEY constraint can be
				 * created with column and nulls ordering which is not possible using normal
				 * ALTER TABLE ADD CONSTRAINT statement.
				 */
				if (constrinfo->contype == 'p' || constrinfo->contype == 'u')
					constrinfo->dobj.dump = DUMP_COMPONENT_NONE;
			}
			break;
		default:
			break;
	}
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

	/* 
	 * We need to re-write the decompiled DEFAULT expression for non-default
	 * database level collation. Else, pg_dump adds explicit COLLATE clause
	 * after the DEFAULT expression as well. This creates two explicit
	 * COLLATE clause during dump -
	 * 	1. For the column itself
	 * 	2. For the default expression
	 * Eg: CREATE TABLE t1(a nvarchar(11) DEFAULT 'default') --> 
	 * CREATE TABLE t1("a" "sys"."nvarchar" DEFAULT 'default'::"sys"."varchar" COLLATE <non_default_collation> COLLATE <non_default_collation>)
	 * This is an invalid syntax, hence it will fail during restore.
	 * Hence we re-write it to:
	 * CREATE TABLE t1("a" "sys"."nvarchar" DEFAULT ('default'::"sys"."varchar" COLLATE <non_default_collation>) COLLATE <non_default_collation>)
	 * by adding parenthesis. As adding parenthesis is optional in PG, 
	 * we update all such default expressions for babelfish
	 */
	if (!isBabelfishDatabase(fout))
		return;
	attrDefInfo->adef_expr = psprintf("(%s)", source);
	free(source);
	source = attrDefInfo->adef_expr;

	if (!strstr(source, runtimeErrStr) ||
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

	/* skip auto-generated array types and non-pltsql functions */
	if (typeInfo->isArray ||
		!OidIsValid(typeInfo->typrelid) ||
		!isPltsqlLanguageOid(fout, funcInfo->lang))
		return;

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
	Oid			pg_type_oid = tbinfo->reltype;
	PQExpBuffer query;
	PGresult	*res;
	int			ntups;

	if(!isBabelfishDatabase(fout) ||
		tbinfo->relkind != RELKIND_RELATION ||
		!OidIsValid(pg_type_oid))
		return false;

	query = createPQExpBuffer();
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
static int
getTsqlTvfType(Archive *fout, const FuncInfo *finfo, char prokind, bool proretset)
{
	TypeInfo *rettype;

	if (!isBabelfishDatabase(fout) || prokind == PROKIND_PROCEDURE || !proretset)
		return PLTSQL_TVFTYPE_NONE;

	rettype = findTypeByOid(finfo->prorettype);

	if (rettype && isPltsqlLanguageOid(fout, finfo->lang))
	{
		if (rettype->typtype == TYPTYPE_COMPOSITE)
			return PLTSQL_TVFTYPE_MSTVF;
		else
			return PLTSQL_TVFTYPE_ITVF;
	}

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

/*
 * getCurrentServerCollationNameSetting - returns current setting of babelfishpg_tsql.server_collation_name guc which
 * should be same as the default collation of _ci_sysname data type.
 * Note that, return result is palloc'd which should be freed by caller
 */
static char *
getCurrentServerCollationNameSetting(Archive *AH)
{
	PGresult *res;
	PQExpBuffer query;
	char *setting;

	query = createPQExpBuffer();
	appendPQExpBuffer(query, "select collname from pg_collation where oid = (select typcollation from pg_type where typname = \'_ci_sysname\');");
	res = ExecuteSqlQueryForSingleRow(AH, query->data);
	setting = pg_strdup(PQgetvalue(res, 0, 0));

	destroyPQExpBuffer(query);
	PQclear(res);

	return setting;
}

/*
 * dumpBabelfishSpecificConfig - dump "alter database %S set ... = /'%s/'" for the babelfish specific GUCs for which
 * the user defined value should be persisted during upgrade e.g., babelfishpg_tsql.server_collation_name and
 * babelfishpg_tsql.default_locale.
 */
void
dumpBabelfishSpecificConfig(Archive *AH, const char *dbname, PQExpBuffer outbuf)
{
	char	*current_server_collation_name = NULL;

	current_server_collation_name = getCurrentServerCollationNameSetting(AH);
	if (current_server_collation_name)
	{
		appendPQExpBuffer(outbuf, "alter database %s set babelfishpg_tsql.restored_server_collation_name = \'%s\';\n", dbname, current_server_collation_name);
		pfree(current_server_collation_name);
	}
}

/*
 * updateExtConfigArray:
 * In some old Babelfish versions, we have incorrectly marked some extension
 * configuration tables as follows:
 * 1. Table sys.babelfish_authid_user_ext has not been marked as config table.
 * 2. Table sys.babelfish_configurations has been marked as configuration table
 *    but it is not supposed to.
 * So the function takes babelfishpg_tsql extension's configuration array(extconfigarray)
 * and replaces OID of sys.babelfish_configurations table with the OID of
 * sys.babelfish_authid_user_ext table. This will ensure that we will dump the data
 * of table sys.babelfish_authid_user_ext instead of sys.babelfish_configurations.
 */
void
updateExtConfigArray(Archive *fout, char ***extconfigarray, int nconfigitems)
{
	char		*bbf_user_ext_tbl_oid;
	Oid			bbf_config_tbl_oid;
	PQExpBuffer query;
	PGresult	*res;
	int			i;
	if (!isBabelfishDatabase(fout))
		return;

	query = createPQExpBuffer();

	/*
	 * Get OIDs of sys.babelfish_authid_user_ext and sys.babelfish_configurations tables.
	 * Later we will replace sys.babelfish_configurations table's OID with the OID of
	 * sys.babelfish_authid_user_ext table in extconfigarray.
	 */
	appendPQExpBufferStr(query,
						 "SELECT oid "
						 "FROM pg_catalog.pg_class "
						 "WHERE relname IN ('babelfish_authid_user_ext', 'babelfish_configurations') "
						 "AND relnamespace = 'sys'::regnamespace "
						 "ORDER BY relname;");

	res = ExecuteSqlQuery(fout, query->data, PGRES_TUPLES_OK);

	if(PQntuples(res) == 2)
	{
		bbf_user_ext_tbl_oid = PQgetvalue(res, 0, 0);
		bbf_config_tbl_oid = atooid(PQgetvalue(res, 1, 0));

		for (i = 0; i < nconfigitems; i++)
		{
			Oid configtbloid = atooid((*extconfigarray)[i]);

			if (configtbloid == bbf_config_tbl_oid)
				(*extconfigarray)[i] = pg_strdup(bbf_user_ext_tbl_oid);
		}
	}

	PQclear(res);
	destroyPQExpBuffer(query);
}

/*
 * prepareForBabelfishDatabaseDump:
 * Populates catalog_table_include_oids list with the OIDs of Babelfish Catalog
 * Configuration tables to selectively dump their data. Additionally, in case of
 * logical database dump, if database exits, we will add all the physical
 * schemas corresponding to that database into schema_include_patterns so that
 * we dump only those physical schemas and all their contained objects.
 */
void
prepareForBabelfishDatabaseDump(Archive *fout, SimpleStringList *schema_include_patterns)
{
	PQExpBuffer	query;
	PGresult	*res;
	int 		ntups;
	int 		i;

	if (!isBabelfishDatabase(fout) || fout->dopt->binary_upgrade)
		return;

	query = createPQExpBuffer();
	/*
	 * Get oids of all the Babelfish catalog configuration tables.
	 * See comments for updateExtConfigArray above for more details
	 * about why we are excluding/including certain tables in the query
	 * below.
	 */
	appendPQExpBufferStr(query,
						 "WITH tableoids AS ("
						 "SELECT unnest(extconfig)::oid AS id "
						 "FROM pg_catalog.pg_extension WHERE extname = 'babelfishpg_tsql') "
						 "SELECT id FROM tableoids WHERE id != 'sys.babelfish_configurations'::regclass " /* Exclude babelfish_configurations table */
						 "UNION SELECT 'sys.babelfish_authid_user_ext'::regclass AS id "); /* Include babelfish_authid_user_ext table */
	res = ExecuteSqlQuery(fout, query->data, PGRES_TUPLES_OK);
	ntups = PQntuples(res);
	for (i = 0; i < ntups; i++)
		simple_oid_list_append(&catalog_table_include_oids, atooid(PQgetvalue(res, i, 0)));

	PQclear(res);
	resetPQExpBuffer(query);
	
	/*
	 * Find out initialize user of current Babelfish database
	 * which is essentially same as owner of the database.
	 */
	appendPQExpBufferStr(query, "SELECT r.rolname FROM pg_roles r "
						 "INNER JOIN pg_database d ON r.oid = d.datdba "
						 "WHERE d.datname = current_database()");
	res = ExecuteSqlQueryForSingleRow(fout, query->data);
	babel_init_user = pstrdup(PQgetvalue(res, 0, 0));

	PQclear(res);
	destroyPQExpBuffer(query);

	/* Return if not logical database dump, continue otherwise. */
	if (bbf_db_name == NULL)
		return;
	/*
	 * Get escaped bbf_db_name to handle special characters in it.
	 * 2*strlen+1 bytes are required for PQescapeString according to the documentation.
	 */
	escaped_bbf_db_name = pg_malloc(2 * strlen(bbf_db_name) + 1);
	PQescapeString(escaped_bbf_db_name, bbf_db_name, strlen(bbf_db_name));

	query = createPQExpBuffer();
	/* get dbid of the given babelfish logical database from sys.babelfish_sysdatabases */
	appendPQExpBuffer(query,
					  "SELECT dbid "
					  "FROM sys.babelfish_sysdatabases "
					  "WHERE name = '%s';",
					  escaped_bbf_db_name);
	res = ExecuteSqlQuery(fout, query->data, PGRES_TUPLES_OK);
	if (PQntuples(res) != 1)
	{
		pg_log_error("Babelfish database \"%s\" does not exists.", escaped_bbf_db_name);
		exit_nicely(1);
	}

	bbf_db_id = atooid(PQgetvalue(res, 0, PQfnumber(res, "dbid")));
	PQclear(res);
	resetPQExpBuffer(query);

	/* Get all the physical schema names from sys.babelfish_namespace_ext with given dbid */
	appendPQExpBuffer(query,
					  "SELECT pg_catalog.quote_ident(nspname) AS nspname "
					  "FROM sys.babelfish_namespace_ext "
					  "WHERE dbid = %d;",
					  bbf_db_id);
	res = ExecuteSqlQuery(fout, query->data, PGRES_TUPLES_OK);
	ntups = PQntuples(res);

	/*
	 * Add all physical schemas corresponding to the logical database into
	 * schema_include_patterns so that we dump only those schemas.
	 */
	for (i = 0; i < ntups; i++)
	{
		char *schema_name;

		schema_name = PQgetvalue(res, i, PQfnumber(res, "nspname"));
		simple_string_list_append(schema_include_patterns, schema_name);
	}

	PQclear(res);
	destroyPQExpBuffer(query);
}

/*
 * setBabelfishDependenciesForLogicalDatabaseDump:
 * Sets required dependencies for babelfish objects.
 */
void
setBabelfishDependenciesForLogicalDatabaseDump(Archive *fout)
{
	int        		i;
	PQExpBuffer		query;
	PGresult		*res;
	TableInfo		*sysdb_table = NULL;
	DumpableObject		*refdobj = NULL;

	if (!isBabelfishDatabase(fout) || fout->dopt->binary_upgrade || fout->dopt->dataOnly)
		return;

	/* Get the OID of sys.babelfish_sysdatabases catalog */
	res = ExecuteSqlQueryForSingleRow(fout, "SELECT oid FROM pg_class "
									  "WHERE relname = 'babelfish_sysdatabases' "
									  "AND relnamespace = 'sys'::regnamespace;");
	sysdb_table = findTableByOid(atooid(PQgetvalue(res, 0, 0)));

	if (!sysdb_table || !sysdb_table->dataObj)
		return;

	PQclear(res);
	query = createPQExpBuffer();
	refdobj = (DumpableObject *) sysdb_table->dataObj;

	/*
	 * Now get the OIDs for following desired catalog tables:
	 * sys.babelfish_namespace_ext
	 * sys.babelfish_extended_properties
	 * sys.babelfish_schema_permissions
	 * sys.babelfish_partition_function
	 * sys.babelfish_partition_scheme
	 * sys.babelfish_partition_depend
	 */
	appendPQExpBufferStr(query,
						 "SELECT oid "
						 "FROM pg_class "
						 "WHERE relname in ('babelfish_schema_permissions', "
						 "'babelfish_namespace_ext', "
						 "'babelfish_partition_function', "
						 "'babelfish_partition_scheme', "
						 "'babelfish_partition_depend', "
						 "'babelfish_extended_properties') "
						 "AND relnamespace = 'sys'::regnamespace "
						 "ORDER BY relname;");
	res = ExecuteSqlQuery(fout, query->data, PGRES_TUPLES_OK);

	/*
	 * Iterate through each row and find the corresponding catalog table by OID,
	 * then make each of those catalog tables dependent upon babelfish_sysdatabases
	 * so that we dump babelfish_sysdatabases table's data before them. This is needed
	 * to generate and handle new "dbid" during logical database restore.
	 */
	for (i = 0; i < PQntuples(res); i++)
	{
		TableInfo *tab = findTableByOid(atooid(PQgetvalue(res, i, 0)));

		if(tab && tab->dataObj)
		{
			DumpableObject *dobj = (DumpableObject *) tab->dataObj;
			addObjectDependency(dobj, refdobj->dumpId);
		}
	}

	PQclear(res);
	destroyPQExpBuffer(query);
}

/*
 * addFromClauseForLogicalDatabaseDump:
 * Helper function for fixCursorForBbfCatalogTableData and fixCopyCommand functions.
 * Responsible for adding a FROM clause to the buffer so as to dump catalog data
 * corresponding to specified logical database.
 */
static void
addFromClauseForLogicalDatabaseDump(PQExpBuffer buf, TableInfo *tbinfo)
{
	if (strcmp(tbinfo->dobj.name, "babelfish_sysdatabases") == 0)
	{
		/*
		 * Dump database catalog entry for specified logical database unless
		 * it's a builtin database (dbid 1, 2, 3 or 4), in which case the db
		 * will already be present in the target server so no need to dump
		 * catalog entry for it.
		 */
		appendPQExpBuffer(buf, " FROM ONLY %s a WHERE a.dbid = %d AND a.dbid > 4",
						  fmtQualifiedDumpable(tbinfo), bbf_db_id);
	}
	else if (strcmp(tbinfo->dobj.name, "babelfish_namespace_ext") == 0)
	{
		appendPQExpBuffer(buf, " FROM ONLY %s a WHERE a.dbid = %d "
						  "AND a.nspname NOT IN "
						  "('master_dbo', 'master_guest', "
						  "'msdb_dbo', 'msdb_guest', "
						  "'tempdb_dbo', 'tempdb_guest') ",
						  fmtQualifiedDumpable(tbinfo), bbf_db_id);
	}
	else if (strcmp(tbinfo->dobj.name, "babelfish_view_def") == 0 ||
			 strcmp(tbinfo->dobj.name, "babelfish_extended_properties") == 0 ||
			 strcmp(tbinfo->dobj.name, "babelfish_schema_permissions") == 0 ||
			 strcmp(tbinfo->dobj.name, "babelfish_partition_function") == 0 ||
			 strcmp(tbinfo->dobj.name, "babelfish_partition_scheme") == 0 ||
			 strcmp(tbinfo->dobj.name, "babelfish_partition_depend") == 0)
		appendPQExpBuffer(buf, " FROM ONLY %s a WHERE a.dbid = %d",
						  fmtQualifiedDumpable(tbinfo), bbf_db_id);
	else if (strcmp(tbinfo->dobj.name, "babelfish_function_ext") == 0)
		appendPQExpBuffer(buf, " FROM ONLY %s a "
						  "INNER JOIN sys.babelfish_namespace_ext b "
						  "ON a.nspname = b.nspname "
						  "WHERE b.dbid = %d",
						  fmtQualifiedDumpable(tbinfo), bbf_db_id);
	else if(strcmp(tbinfo->dobj.name, "babelfish_authid_user_ext") == 0)
	{
		appendPQExpBuffer(buf, " FROM ONLY %s a "
						  "INNER JOIN sys.babelfish_sysdatabases b "
						  "ON a.database_name = b.name COLLATE \"C\" "
						  "WHERE b.dbid = %d "
						  "AND a.rolname NOT IN "
						  "('master_dbo', 'master_db_owner', 'master_guest', "
						  "'msdb_dbo', 'msdb_db_owner', 'msdb_guest', "
						  "'tempdb_dbo', 'tempdb_db_owner', 'tempdb_guest') ",
						  fmtQualifiedDumpable(tbinfo), bbf_db_id);
	}
	else
	{
		pg_log_error("Unrecognized Babelfish catalog table %s.", fmtQualifiedDumpable(tbinfo));
		exit_nicely(1);
	}
}

/*
 * addFromClauseForPhysicalDatabaseDump:
 * Helper function for fixCursorForBbfCatalogTableData and fixCopyCommand 
 * functions. Responsible for adding a FROM clause for physical database dump 
 * to the buffer so as to not dump default data since it will be already present
 * in the Babelfish database.
 */
static void
addFromClauseForPhysicalDatabaseDump(PQExpBuffer buf, TableInfo *tbinfo)
{
	if (strcmp(tbinfo->dobj.name, "babelfish_sysdatabases") == 0)
	{
		/*
		 * The dbid 1,2,3 and 4 are reserved ids and will already be present 
		 * in the restored server, so no need to dump catalog entry for it.
		 */
		appendPQExpBuffer(buf, " FROM ONLY %s a WHERE a.dbid > 4",
						  fmtQualifiedDumpable(tbinfo));
	}
	else if (strcmp(tbinfo->dobj.name, "babelfish_namespace_ext") == 0)
	{
		/*
		 * The dbid 1,2,3 and 4 are reserved ids and will already be present in the
		 * restored server, we need to dump nsps that are created in non-builtin
		 * databases or created by user in non-builtin databases.
		 */
		appendPQExpBuffer(buf, " FROM ONLY %s a WHERE a.dbid > 4 "
						 "OR ( a.dbid < 4 AND a.orig_name NOT IN ('dbo', 'guest'))",
						  fmtQualifiedDumpable(tbinfo));
	}
	else if(strcmp(tbinfo->dobj.name, "babelfish_authid_user_ext") == 0)
	{
		appendPQExpBuffer(buf, " FROM ONLY %s a "
						  "WHERE a.rolname NOT IN "
						  "('master_dbo', 'master_db_owner', 'master_guest', "
						  "'tempdb_dbo', 'tempdb_db_owner', 'tempdb_guest', "
						  "'msdb_dbo', 'msdb_db_owner', 'msdb_guest')",
						  fmtQualifiedDumpable(tbinfo));
	}
	else if(strcmp(tbinfo->dobj.name, "babelfish_authid_login_ext") == 0)
		appendPQExpBuffer(buf, " FROM ONLY %s a "
						"WHERE a.rolname NOT IN ('sysadmin', 'bbf_role_admin', '%s')", /* Do not dump sysadmin, bbf_role_admin and Babelfish initialize user */
						fmtQualifiedDumpable(tbinfo), babel_init_user);
	else if(strcmp(tbinfo->dobj.name, "babelfish_domain_mapping") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_function_ext") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_view_def") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_server_options") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_extended_properties") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_schema_permissions") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_partition_function") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_partition_scheme") == 0 ||
			strcmp(tbinfo->dobj.name, "babelfish_partition_depend") == 0)
		appendPQExpBuffer(buf, " FROM ONLY %s a",
						  fmtQualifiedDumpable(tbinfo));
	else
	{
		pg_log_error("Unrecognized Babelfish catalog table %s.", fmtQualifiedDumpable(tbinfo));
		exit_nicely(1);
	}
}

/*
 * addFromClauseForBabelfishCatalogTable:
 * Wrapper function to add FROM clause for a Babelfish catalog table.
 */
void
addFromClauseForBabelfishCatalogTable(PQExpBuffer buf, TableInfo *tbinfo)
{
	/* Add FROM clause differently for physical or logical database dump. */
	if (bbf_db_name == NULL)
		addFromClauseForPhysicalDatabaseDump(buf, tbinfo);
	else
		addFromClauseForLogicalDatabaseDump(buf, tbinfo);
}

/*
 * fixCursorForBbfCatalogTableData:
 * Prepare custom cursor for all Babelfish catalog tables to selectively dump 
 * the data corresponding to specified physical/logical database.
 */
static void
fixCursorForBbfCatalogTableData(Archive *fout, TableInfo *tbinfo, PQExpBuffer buf, int *nfields, char *attgenerated)
{
	int 	i;
	bool	is_builtin_db = false;
	bool	is_bbf_usr_ext_tab = false;
	bool	is_bbf_sysdatabases_tab = false;
	bool	is_bbf_partition_function_tab = false;
	bool	is_bbf_partition_scheme_tab = false;
	bool	has_sqlv_col = hasSqlvariantColumn(tbinfo);

	/* Return if the table is not a Babelfish configuration table. */
	if (!isBabelfishConfigTable(fout, tbinfo))
		return;

	if (bbf_db_name != NULL)
		is_builtin_db = (pg_strcasecmp(bbf_db_name, "master") == 0 ||
				pg_strcasecmp(bbf_db_name, "tempdb") == 0 ||
				pg_strcasecmp(bbf_db_name, "msdb") == 0)
				? true : false;

	/* 
	 * Remember if it is babelfish_authid_user_ext, babelfish_sysdatabases,
	 * babelfish_partition_function and babelfish_partition_scheme catalog table
	 * because these catalog tables contain generated IDs which should not be dumped
	 * for logical database.
	 */
	if (strcmp(tbinfo->dobj.name, "babelfish_authid_user_ext") == 0)
		is_bbf_usr_ext_tab = true;
	if (strcmp(tbinfo->dobj.name, "babelfish_sysdatabases") == 0)
		is_bbf_sysdatabases_tab = true;
	if (strcmp(tbinfo->dobj.name, "babelfish_partition_function") == 0)
		is_bbf_partition_function_tab = true;
	if (strcmp(tbinfo->dobj.name, "babelfish_partition_scheme") == 0)
		is_bbf_partition_scheme_tab = true;

	resetPQExpBuffer(buf);
	appendPQExpBufferStr(buf, "DECLARE _pg_dump_cursor CURSOR FOR SELECT ");
	*nfields = 0;
	for (i = 0; i < tbinfo->numatts; i++)
	{
		if (tbinfo->attisdropped[i])
			continue;
		if (tbinfo->attgenerated[i] && (fout->dopt->column_inserts || has_sqlv_col))
			continue;

		/*
		 * We need to skip owner column of babelfish_sysdatabases table as it might be
		 * referencing Babelfish initialize user which we do not include in dump. We will
		 * populate this column during restore with the initialize user of target database.
		 */
		if (is_bbf_sysdatabases_tab && strcmp(tbinfo->attnames[i], "owner") == 0)
			continue;
		/*
		 * 1. Skip dbid column for logical database dump, we will generate new 
		 *    database id during restore. We will still dump dbid for builtin 
		 *    databases since we don't need to regenerate it during restore as 
		 *    dbids are fixed for builtin databases.
		 * 2. Skip function_id and scheme_id column of babelfish_partition_function
		 *    and babelfish_partition_scheme catalog respectively for logical database dump,
		 *    we will generate new function_id and scheme_id during restore.
		 */
		else if (bbf_db_name != NULL)
		{
			if ((!is_builtin_db && strcmp(tbinfo->attnames[i], "dbid") == 0) || 
					(is_bbf_partition_function_tab && (strcmp(tbinfo->attnames[i], "function_id") == 0)) ||
					(is_bbf_partition_scheme_tab && (strcmp(tbinfo->attnames[i], "scheme_id") == 0)))
			{
				/* also mark this column as dropped */
				tbinfo->attisdropped[i] = true;
				continue;
			}
		}

		if (*nfields > 0)
			appendPQExpBufferStr(buf, ", ");
		/*
		 * Since we don't dump logins while dumping a logical database, we also need to
		 * make sure that we do not dump any login names mapped to the users in
		 * babelfish_authid_user_ext table. For that reason, we just dump an empty string ('')
		 * for login_name column in babelfish_authid_user_ext table, which is what have been
		 * used as a default value for this column historically.
		 */
		if (bbf_db_name != NULL && is_bbf_usr_ext_tab && strcmp(tbinfo->attnames[i], "login_name") == 0)
			appendPQExpBufferStr(buf, "'' AS login_name");
		else if (tbinfo->attgenerated[i])
			appendPQExpBufferStr(buf, "NULL");
		else
		{
			appendPQExpBufferStr(buf, "a.");
			appendPQExpBufferStr(buf, fmtId(tbinfo->attnames[i]));
		}
		attgenerated[*nfields] = tbinfo->attgenerated[i];
		(*nfields)++;
	}
}

/*
 * fixCopyCommand:
 * Fixes column list in a COPY command as well as modifies the command
 * for all Babelfish catalog tables to selectively dump the data corresponding
 * to specified physical/logical database.
 * isFrom decides whether we are copying FROM or TO.
 */
void
fixCopyCommand(Archive *fout, PQExpBuffer copyBuf, TableInfo *tbinfo, bool isFrom)
{
	PQExpBuffer	q;
	int			i;
	bool		is_builtin_db = false;
	bool		needComma = false;
	bool		is_bbf_usr_ext_tab = false;
	bool		is_bbf_sysdatabases_tab = false;
	bool		is_bbf_partition_scheme_tab = false;

	/*
	 * Return if not a Babelfish database, or if the table is not a Babelfish
	 * configuration table.
	 */
	if (!isBabelfishConfigTable(fout, tbinfo))
		return;

	if (bbf_db_name != NULL)
		is_builtin_db = (pg_strcasecmp(bbf_db_name, "master") == 0 ||
				pg_strcasecmp(bbf_db_name, "tempdb") == 0 ||
				pg_strcasecmp(bbf_db_name, "msdb") == 0)
				? true : false;

	/* 
	 * Remember if it is babelfish_authid_user_ext, babelfish_sysdatabases
	 * and babelfish_partition_scheme catalog table
	 * because these catalog tables contain generated IDs which should not be dumped
	 * for logical database.
	 */
	if (strcmp(tbinfo->dobj.name, "babelfish_authid_user_ext") == 0)
		is_bbf_usr_ext_tab = true;
	if (strcmp(tbinfo->dobj.name, "babelfish_sysdatabases") == 0)
		is_bbf_sysdatabases_tab = true;
	if (strcmp(tbinfo->dobj.name, "babelfish_partition_scheme") == 0)
		is_bbf_partition_scheme_tab = true;

	q = createPQExpBuffer();
	for (i = 0; i < tbinfo->numatts; i++)
	{
		if (tbinfo->attisdropped[i])
			continue;
		if (tbinfo->attgenerated[i])
			continue;
		/*
		 * Skip dbid column, we will generate new database id during restore.
		 * We will still dump dbid for builtin databases since we don't need to
		 * regenerate it during restore as dbids are fixed for builtin databases.
		 */
		if (bbf_db_name != NULL && !is_builtin_db && strcmp(tbinfo->attnames[i], "dbid") == 0)
			continue;
		/*
		 * We need to skip owner column of babelfish_sysdatabases table as it might be
		 * referencing Babelfish initialize user which we do not include in dump. We will
		 * populate this column during restore with the initialize user of target database.
		 */
		else if (is_bbf_sysdatabases_tab && strcmp(tbinfo->attnames[i], "owner") == 0)
			continue;
		/*
		 * Skip scheme_id column of babelfish_partition_scheme catalog
		 * for logical database dump, we will generate new scheme_id during restore.
		 */
		else if (bbf_db_name != NULL && is_bbf_partition_scheme_tab && (strcmp(tbinfo->attnames[i], "scheme_id") == 0))
			continue;

		if (needComma)
			appendPQExpBufferStr(q, ", ");

		if (isFrom)
			appendPQExpBufferStr(q, fmtId(tbinfo->attnames[i]));
		else
		{
			/*
			 * Since we don't dump logins while dumping a logical database, we also need to
			 * make sure that we do not dump any login names mapped to the users in
			 * babelfish_authid_user_ext table. For that reason, we just dump an empty string ('')
			 * for login_name column in babelfish_authid_user_ext table, which is what have been
			 * used as a default value for this column historically.
			 */
			if (bbf_db_name != NULL && is_bbf_usr_ext_tab && strcmp(tbinfo->attnames[i], "login_name") == 0)
				appendPQExpBufferStr(q, "''");
			/*
			 * In case of COPY TO, we are going to form SELECT statement
			 * which needs table reference in column names.
			 */
			else
				appendPQExpBuffer(q, "a.%s", fmtId(tbinfo->attnames[i]));
		}
		needComma = true;
	}

	resetPQExpBuffer(copyBuf);
	if (isFrom)
		appendPQExpBuffer(copyBuf, "COPY %s (%s) FROM stdin;\n",
						  fmtQualifiedDumpable(tbinfo),
						  q->data);
	else
	{
		appendPQExpBuffer(copyBuf, "COPY (SELECT %s ",
						  q->data);
		addFromClauseForBabelfishCatalogTable(copyBuf, tbinfo);
		appendPQExpBufferStr(copyBuf, ") TO stdout;");
	}
	destroyPQExpBuffer(q);
}

/*
 * bbfIsDumpWithInsert:
 * Returns true if table in Babelfish Database is to be dumped with INSERT mode.
 * Currently we dump tables with sql_variant columns with INSERT operations to
 * correctly restore the metadata of the base datatype, which is not directly
 * possible with COPY statements.
 */
bool
bbfIsDumpWithInsert(Archive *fout, TableInfo *tbinfo)
{
	return (isBabelfishDatabase(fout) &&
			hasSqlvariantColumn(tbinfo));
}

/*
 * hasSqlvariantColumn:
 * Returns true if any of the columns in table is a sqlvariant data type column
 */
static bool
hasSqlvariantColumn(TableInfo *tbinfo)
{
	for (int i = 0; i < tbinfo->numatts; i++)
		if (strstr(tbinfo->atttypnames[i],
				quote_all_identifiers ? "\"sys\".\"sql_variant\"" : "sys.sql_variant"))
					return true;
	return false;
}

/*
 * getMbstrlen:
 * returns the length of a multibyte string
 */
static int
getMbstrlen(const char *mbstr, Archive *fout)
{
	int len = 0;
	if (!mbstr)
		return 0;
	while (*mbstr){
		mbstr += PQmblen(mbstr, fout->encoding);
		len++;
	}
	return len;
}

/*
 * fixCursorForBbfSqlvariantTableData:
 * Prepare custom cursor for all Babelfish tables with atleast one sql_variant
 * datatype column to correctly dump sql_variant data.
 *
 * Returns total number of fields in the cursor which is the sum of existing
 * nfields and the extra fields added for each sql_variant column.
 */
static int
fixCursorForBbfSqlvariantTableData( Archive *fout,
									TableInfo *tbinfo,
									PQExpBuffer query,
									int nfields,
									int **sqlvar_metadata_pos)
{
	int orig_nfields = 0;
	PQExpBuffer buf = createPQExpBuffer();
	bool is_catalog_table = isBabelfishConfigTable(fout, tbinfo);
	int attlen;

	if (!hasSqlvariantColumn(tbinfo))
		return nfields;

	*sqlvar_metadata_pos = (int *) pg_malloc0(tbinfo->numatts * sizeof(int));
	for (int i = 0; i < tbinfo->numatts; i++)
	{
		if (tbinfo->attisdropped[i])
			continue;
		if (tbinfo->attgenerated[i])
			continue;
		attlen = strlen(tbinfo->atttypnames[i]);
		/* Skip TSQL ROWVERSION/TIMESTAMP column, it should be re-generated during restore. */
		if (pg_strcasecmp(tbinfo->atttypnames[i],
				quote_all_identifiers ? "\"sys\".\"rowversion\"" : "sys.rowversion") == 0 ||
			pg_strcasecmp(tbinfo->atttypnames[i],
				quote_all_identifiers ? "\"sys\".\"timestamp\"" : "sys.timestamp") == 0)
		if ((quote_all_identifiers ?
				(attlen == 18) && (pg_strcasecmp(tbinfo->atttypnames[i], "\"sys\".\"rowversion\"") == 0)
				: (attlen == 14) && (pg_strcasecmp(tbinfo->atttypnames[i], "sys.rowversion") == 0)) ||
			(quote_all_identifiers ?
				(attlen == 17) && (pg_strcasecmp(tbinfo->atttypnames[i], "\"sys\".\"timestamp\"") == 0)
				: (attlen == 13) && (pg_strcasecmp(tbinfo->atttypnames[i], "sys.timestamp") == 0)))
			continue;

		/*
		 * To find the basetype and bytelength of string data types we
		 * invoke sys.sql_variant_property and sys.datalength function on
		 * the sqlvariant column. These extra columns are added at the end of
		 * the select cursor query so that they do not interfere with
		 * expected dump behaviour.
		 */
		if (quote_all_identifiers ? 
				(attlen == 19) && (pg_strcasecmp(tbinfo->atttypnames[i], "\"sys\".\"sql_variant\"") == 0)
				: (attlen == 15) && (pg_strcasecmp(tbinfo->atttypnames[i], "sys.sql_variant") == 0))
		{
			/*
			 * We need to qualify the column names with table alias 'a' if it is a
			 * Babelfish catalog table to match the convention of fixCursorForBbfCatalogTableData
			 * function.
			 */
			appendPQExpBufferStr(buf, ", sys.SQL_VARIANT_PROPERTY(");
			if (is_catalog_table)
				appendPQExpBufferStr(buf, "a.");
			appendPQExpBuffer(buf, "%s, 'BaseType')", fmtId(tbinfo->attnames[i]));
			appendPQExpBufferStr(buf, ", sys.datalength(");
			if (is_catalog_table)
				appendPQExpBufferStr(buf, "a.");
			appendPQExpBuffer(buf, "%s)", fmtId(tbinfo->attnames[i]));
			appendPQExpBuffer(buf, ", 0"); /* to indicate if it is array or not */
			(*sqlvar_metadata_pos)[orig_nfields] = nfields;
			nfields = nfields + 3;
		}
		/* array of sql_variant */
		else if (quote_all_identifiers ?
				(attlen == 21) && (pg_strcasecmp(tbinfo->atttypnames[i], "\"sys\".\"sql_variant\"[]") == 0)
				: (attlen == 17) && (pg_strcasecmp(tbinfo->atttypnames[i], "sys.sql_variant[]") == 0))
		{
			/*
			 * We need additional handling for an array of sql_variant because each value in the
			 * array will have a different base type and byte length. Here, instead of adding normal
			 * columns for base type and byte length as extra columns, we will add arrays of them which
			 * will be constructed by invoking the sys.sql_variant_property and sys.datalength functions
			 * on each value of the array.
			 */
			appendPQExpBufferStr(buf, ", (SELECT array_agg(sys.SQL_VARIANT_PROPERTY(t1, 'BaseType')) FROM unnest(");
			if (is_catalog_table) /* qualify the column names with table alias if it is a babelfish catalog table */
				appendPQExpBufferStr(buf, "a.");
			appendPQExpBuffer(buf, "%s) AS t1)", fmtId(tbinfo->attnames[i]));

			appendPQExpBufferStr(buf, ", (SELECT array_agg(sys.datalength(t2)) FROM unnest(");
			if (is_catalog_table) /* qualify the column names with table alias if it is a babelfish catalog table */
				appendPQExpBufferStr(buf, "a.");
			appendPQExpBuffer(buf, "%s) AS t2)", fmtId(tbinfo->attnames[i]));
			appendPQExpBuffer(buf, ", 1"); /* to indicate if it is array or not */
			(*sqlvar_metadata_pos)[orig_nfields] = nfields;
			nfields = nfields + 3;
		}
		orig_nfields++;
	}
	appendPQExpBufferStr(query, buf->data);
	destroyPQExpBuffer(buf);
	return nfields;
}

/*
 * castSqlvariantToBasetypeHelper:
 * Helper function to modify the sql_variant data in the dump file by adding
 * explicit cast to its basetype in order to preserve the metadata of data type by using the
 * provided information of type and datalength.
 */
static void
castSqlvariantToBasetypeHelper(Archive *fout, char *value, char *type, int datalength)
{
	PQExpBuffer q;
	int precision;
	int scale;
	int i;

	q = createPQExpBuffer();
	appendStringLiteralAH(q, value, fout);
	archprintf(fout, "CAST(%s AS ", q->data);
	/* data types defined in sys schema should be handled separately */
	if (!pg_strcasecmp(type, "datetime") || !pg_strcasecmp(type, "datetimeoffset")
		|| !pg_strcasecmp(type, "smalldatetime") || !pg_strcasecmp(type, "uniqueidentifier")
		|| !pg_strcasecmp(type, "smallmoney") || !pg_strcasecmp(type, "tinyint")
		|| !pg_strcasecmp(type, "money") || !pg_strcasecmp(type, "bit")
		|| !pg_strcasecmp(type, "datetime2") || !pg_strcasecmp(type, "datetimeoffset"))
	{
		archprintf(fout, "%s.",fmtId("sys"));
		archprintf(fout, "%s", fmtId(type));
	}
	/* typecast with appropriate typmod */
	else if (!pg_strcasecmp(type, "nvarchar") || !pg_strcasecmp(type, "varbinary")|| !pg_strcasecmp(type, "binary"))
	{
		archprintf(fout, "%s.",fmtId("sys"));
		if (datalength)
			archprintf(fout, "%s(%d)", fmtId(type), datalength);
		else
			archprintf(fout, "%s", fmtId(type));
	}
	/* nchar to be handled separately for multi-byte chcaracters */
	else if (!pg_strcasecmp(type, "nchar"))
	{
		datalength = getMbstrlen(value, fout);
		archprintf(fout, "%s.",fmtId("sys"));
		if (datalength)
			archprintf(fout, "%s(%d)", fmtId(type), datalength);
		else
			archprintf(fout, "%s", fmtId(type));
	}
	/* when basetype is char we typecast value to bpchar */
	else if (!pg_strcasecmp(type, "char"))
	{
		archprintf(fout, "%s.",fmtId("sys"));
		if (datalength)
			archprintf(fout, "%s(%d)", fmtId("bpchar"), datalength);
		else
			archprintf(fout, "%s", fmtId(type));
	}
	/* typecast numeric/decimal values with appropriate scale and precision */
	else if (!pg_strcasecmp(type, "numeric") || !pg_strcasecmp(type, "decimal")){
		scale = 0;
		precision = strlen(value);
		i = precision - 1;

		if (value[0] == '-')
			precision--;

		while (i >= 0){
			if (value[i--] == '.'){
				precision--;
				break;
			}
			scale++;
		}
		/* if no decimal found then scale will be zero */
		if (i < 0) scale = 0;

		archprintf(fout, "%s(%d, %d)", fmtId(type), precision, scale);
	}
	else
		archprintf(fout, "%s",type);
	archputs(")", fout);
	destroyPQExpBuffer(q);
}

/*
 * castSqlvariantToBasetype:
 * Modify INSERT query in dump file by adding a CAST expression for a sql_variant
 * column data entry in order to preserve the metadata of data type otherwise
 * lost during restore.
 */
void
castSqlvariantToBasetype(PGresult *res,
						Archive *fout,
						int row, /* row number */
						int field, /* column number */
						int sqlvariant_pos) /* position of columns with metadata of sql_variant column at field */
{
	char* value = PQgetvalue(res, row, field);
	char* type = PQgetvalue(res, row, sqlvariant_pos);
	char* datalength = PQgetvalue(res, row, sqlvariant_pos + 1);
	bool is_array = atoi(PQgetvalue(res, row, sqlvariant_pos + 2));

	if (!is_array)
	{
		castSqlvariantToBasetypeHelper(fout, value, type, atoi(datalength));
	}
	else /* array of sql_variant */
	{
		char **value_items = NULL;
		char **datalength_items = NULL;
		char **type_items = NULL;
		int nitems = 0;
		int i;
		
		/* deconstruct the array into individual items */
		parsePGArray(value, &value_items, &nitems);
		parsePGArray(type, &type_items, &nitems);
		parsePGArray(datalength, &datalength_items, &nitems);

		/* dump array constructor */
		archputs("array[", fout);
		for (i = 0; i < nitems; i++)
		{
			/* dump each values after adding explicit cast to basetype */
			castSqlvariantToBasetypeHelper(fout, value_items[i], type_items[i], atoi(datalength_items[i]));
			if (i != nitems - 1)
				archputs(", ", fout);
		}
		archputs("]", fout);

		free(value_items);
		free(datalength_items);
		free(type_items);
	}
}

/*
 * fixCursorForBbfTableData:
 * Common wrapper for fixCursorForBbfCatalogTableData and fixCursorForBbfSqlvariantTableData
 * functions. This handles preparation of custom cursor for all Babelfish catalog tables and
 * tables with sql_variant column(s).
 */
void
fixCursorForBbfTableData(Archive *fout,
						 TableInfo *tbinfo,
						 PQExpBuffer buf,
						 int *nfields,
						 int *nfields_new,
						 char *attgenerated,
						 int **sqlvar_metadata_pos)
{
	/* Return if it is not a Babelfish database */
	if (!isBabelfishDatabase(fout))
		return;

	fixCursorForBbfCatalogTableData(fout, tbinfo, buf, nfields, attgenerated);
	*nfields_new = fixCursorForBbfSqlvariantTableData(fout, tbinfo, buf, *nfields,
													  sqlvar_metadata_pos);
}

/*
 * babelfishDumpOpclassHelper - This particular helper function would be helpful
 * to dump Babelfish operator class created on the top of built-in data types of
 * the Postgres. For example, Operator class sys.int_numeric for the type int4.
 * This is needed because of some bug in postgres due to which Operarors and
 * Support functions are not being dumped correctly for user defined operator
 * class defined for built-in datatypes.
 */
void
babelfishDumpOpclassHelper(Archive *fout, const OpclassInfo *opcinfo, PQExpBuffer buff, bool *needComma)
{
	PQExpBuffer	query;
	PGresult	*res;
	int			i_opfnamespace;
	int			i_opfname;
	char		*opfnamespace;
	char		*opfname;
	const char	*str = NULL;
	const char 	*opclass = fmtQualifiedDumpable(opcinfo);


	/* Firstly check that Operator class is part of Babelfish */
	if (pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"int_numeric\"" : "sys.int_numeric") != 0 &&
		pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"numeric_int\"" : "sys.numeric_int") != 0 &&
		pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"int2_numeric\"" : "sys.int2_numeric") != 0 &&
		pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"numeric_int2\"" : "sys.numeric_int2") != 0 &&
		pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"int8_numeric\"" : "sys.int8_numeric") != 0 &&
		pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"numeric_int8\"" : "sys.numeric_int8") != 0)
		return;

	query = createPQExpBuffer();

	/* Get the details of Operator family */
	appendPQExpBuffer(query, "SELECT opfnamespace::regnamespace, "
					  "opfname "
					  "FROM pg_opclass c JOIN  pg_opfamily f ON c.opcfamily = f.oid "
					  "WHERE c.oid = '%u'::pg_catalog.oid",
					  opcinfo->dobj.catId.oid);

	res = ExecuteSqlQueryForSingleRow(fout, query->data);

	i_opfnamespace = PQfnumber(res, "opfnamespace");
	i_opfname = PQfnumber(res, "opfname");

	opfnamespace = PQgetvalue(res, 0, i_opfnamespace);
	opfname = PQgetvalue(res, 0, i_opfname);

	destroyPQExpBuffer(query);
	/* Final checks that Operator class is part of built-in operator family. */
	if (opfnamespace == NULL || opfname == NULL)
	{
		PQclear(res);
		return;
	}

	if (strcasecmp(opfnamespace, "\"pg_catalog\"") != 0 ||
		strcasecmp(opfname, "integer_ops") != 0)
	{
		PQclear(res);
		return;
	}

	PQclear(res);

	if (pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"int_numeric\"" : "sys.int_numeric") == 0)
	{
		str = quote_all_identifiers ?
				"OPERATOR 1 \"sys\".< (int4, numeric) ,\n	"
				"OPERATOR 2 \"sys\".<= (int4, numeric) ,\n	"
				"OPERATOR 3 \"sys\".= (int4, numeric) ,\n	"
				"OPERATOR 4 \"sys\".>= (int4, numeric) ,\n	"
				"OPERATOR 5 \"sys\".> (int4, numeric) ,\n	"
				"FUNCTION 1 \"sys\".\"int4_numeric_cmp\"(int4, numeric) " :
				"OPERATOR 1 sys.< (int4, numeric) ,\n	"
				"OPERATOR 2 sys.<= (int4, numeric) ,\n	"
				"OPERATOR 3 sys.= (int4, numeric) ,\n	"
				"OPERATOR 4 sys.>= (int4, numeric) ,\n	"
				"OPERATOR 5 sys.> (int4, numeric) ,\n	"
				"FUNCTION 1 sys.int4_numeric_cmp(int4, numeric) ";
	}

	if (pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"numeric_int\"" : "sys.numeric_int") == 0)
	{
		str = quote_all_identifiers ?
				"OPERATOR 1 \"sys\".< (numeric, int4) ,\n	"
				"OPERATOR 2 \"sys\".<= (numeric, int4) ,\n	"
				"OPERATOR 3 \"sys\".= (numeric, int4) ,\n	"
				"OPERATOR 4 \"sys\".>= (numeric, int4) ,\n	"
				"OPERATOR 5 \"sys\".> (numeric, int4) ,\n	"
				"FUNCTION 1 \"sys\".\"numeric_int4_cmp\"(numeric, int4) " :
				"OPERATOR 1 sys.< (numeric, int4) ,\n	"
				"OPERATOR 2 sys.<= (numeric, int4) ,\n	"
				"OPERATOR 3 sys.= (numeric, int4) ,\n	"
				"OPERATOR 4 sys.>= (numeric, int4) ,\n	"
				"OPERATOR 5 sys.> (numeric, int4) ,\n	"
				"FUNCTION 1 sys.numeric_int4_cmp(numeric, int4) ";
	}

	if (pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"int2_numeric\"" : "sys.int2_numeric") == 0)
	{
		str = quote_all_identifiers ?
			"OPERATOR 1 \"sys\".< (int2, numeric) ,\n	"
			"OPERATOR 2 \"sys\".<= (int2, numeric) ,\n	"
			"OPERATOR 3 \"sys\".= (int2, numeric) ,\n	"
			"OPERATOR 4 \"sys\".>= (int2, numeric) ,\n	"
			"OPERATOR 5 \"sys\".> (int2, numeric) ,\n	"
			"FUNCTION 1 \"sys\".\"int2_numeric_cmp\"(int2, numeric) " :
			"OPERATOR 1 sys.< (int2, numeric) ,\n	"
			"OPERATOR 2 sys.<= (int2, numeric) ,\n	"
			"OPERATOR 3 sys.= (int2, numeric) ,\n	"
			"OPERATOR 4 sys.>= (int2, numeric) ,\n	"
			"OPERATOR 5 sys.> (int2, numeric) ,\n	"
			"FUNCTION 1 sys.int2_numeric_cmp(int2, numeric) ";
	}

	if (pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"numeric_int2\"" : "sys.numeric_int2") == 0)
	{
		str = quote_all_identifiers ?
				"OPERATOR 1 \"sys\".< (numeric, int2) ,\n	"
				"OPERATOR 2 \"sys\".<= (numeric, int2) ,\n	"
				"OPERATOR 3 \"sys\".= (numeric, int2) ,\n	"
				"OPERATOR 4 \"sys\".>= (numeric, int2) ,\n	"
				"OPERATOR 5 \"sys\".> (numeric, int2) ,\n	"
				"FUNCTION 1 \"sys\".\"numeric_int2_cmp\"(numeric, int2) " :
				"OPERATOR 1 sys.< (numeric, int2) ,\n	"
				"OPERATOR 2 sys.<= (numeric, int2) ,\n	"
				"OPERATOR 3 sys.= (numeric, int2) ,\n	"
				"OPERATOR 4 sys.>= (numeric, int2) ,\n	"
				"OPERATOR 5 sys.> (numeric, int2) ,\n	"
				"FUNCTION 1 sys.numeric_int2_cmp(numeric, int2)	";
	}

	if (pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"int8_numeric\"" : "sys.int8_numeric") == 0)
	{
		str = quote_all_identifiers ?
				"OPERATOR 1 \"sys\".< (int8, numeric) ,\n	"
				"OPERATOR 2 \"sys\".<= (int8, numeric) ,\n	"
				"OPERATOR 3 \"sys\".= (int8, numeric) ,\n	"
				"OPERATOR 4 \"sys\".>= (int8, numeric) ,\n	"
				"OPERATOR 5 \"sys\".> (int8, numeric) ,\n	"
				"FUNCTION 1 \"sys\".\"int8_numeric_cmp\"(int8, numeric) " :
				"OPERATOR 1 sys.< (int8, numeric) ,\n	"
				"OPERATOR 2 sys.<= (int8, numeric) ,\n	"
				"OPERATOR 3 sys.= (int8, numeric) ,\n	"
				"OPERATOR 4 sys.>= (int8, numeric) ,\n	"
				"OPERATOR 5 sys.> (int8, numeric) ,\n	"
				"FUNCTION 1 sys.int8_numeric_cmp(int8, numeric) ";
	}

	if (pg_strcasecmp(opclass, quote_all_identifiers ? "\"sys\".\"numeric_int8\"" : "sys.numeric_int8") == 0)
	{
		str = quote_all_identifiers ?
				"OPERATOR 1 \"sys\".< (numeric, int8) ,\n	"
				"OPERATOR 2 \"sys\".<= (numeric, int8) ,\n	"
				"OPERATOR 3 \"sys\".= (numeric, int8) ,\n	"
				"OPERATOR 4 \"sys\".>= (numeric, int8) ,\n	"
				"OPERATOR 5 \"sys\".> (numeric, int8) ,\n	"
				"FUNCTION 1 \"sys\".\"numeric_int8_cmp\"(numeric, int8) " :
				"OPERATOR 1 sys.< (numeric, int8) ,\n	"
				"OPERATOR 2 sys.<= (numeric, int8) ,\n	"
				"OPERATOR 3 sys.= (numeric, int8) ,\n	"
				"OPERATOR 4 sys.>= (numeric, int8) ,\n	"
				"OPERATOR 5 sys.> (numeric, int8) ,\n	"
				"FUNCTION 1 sys.numeric_int8_cmp(numeric, int8) ";
	}

	if(str != NULL)
		appendPQExpBufferStr(buff, str);
	
	/*
	 * set needComma to true so that original pg_dump does not dump unnecessary option
	 * Check when STORAGE option will be dumped in dumpOpclass(...).  
	 */
	*needComma = true;
}

/*
 * Dump the index if it is a UNIQUE/PRIMARY KEY constraint in Babelfish database.
 * We will use this index later to create the constraint.
 * Returns true if we should dump the index, false otherwise.
 */
bool
bbfShouldDumpIndex(Archive *fout, const IndxInfo *indxinfo)
{
	ConstraintInfo *constrinfo = NULL;

	if (!isBabelfishDatabase(fout) || indxinfo->indexconstraint == 0)
		return false;

	constrinfo = (ConstraintInfo *) findObjectByDumpId(indxinfo->indexconstraint);

	if (constrinfo->contype == 'p' || constrinfo->contype == 'u')
		return true;

	return false;
}

/*
 * dumpBabelfishConstrIndex
 * Dump given UNIQUE/PRIMARY KEY constraint using given index.
 */
void
dumpBabelfishConstrIndex(Archive *fout, const IndxInfo *indxinfo,
                         PQExpBuffer q, PQExpBuffer delq)
{
	TableInfo   	*tbinfo;
	char        	*foreign;
	ConstraintInfo	*constrinfo = NULL;

	if (!isBabelfishDatabase(fout) || indxinfo->indexconstraint == 0)
		return;

	constrinfo = (ConstraintInfo *) findObjectByDumpId(indxinfo->indexconstraint);
	tbinfo = constrinfo->contable;
	foreign = tbinfo &&
		tbinfo->relkind == RELKIND_FOREIGN_TABLE ? "FOREIGN " : "";

	appendPQExpBuffer(q, "ALTER %sTABLE ONLY %s\n", foreign,
					  fmtQualifiedDumpable(tbinfo));
	appendPQExpBufferStr(q,
						 constrinfo->contype == 'p' ? "ADD PRIMARY KEY" : "ADD UNIQUE");
	appendPQExpBuffer(q, " USING INDEX %s",
					  fmtId(indxinfo->dobj.name));

	if (constrinfo->condeferrable)
	{
		appendPQExpBufferStr(q, " DEFERRABLE");
		if (constrinfo->condeferred)
			appendPQExpBufferStr(q, " INITIALLY DEFERRED");
	}
	appendPQExpBufferStr(q, ";\n");

	resetPQExpBuffer(delq);
	appendPQExpBuffer(delq, "ALTER %sTABLE ONLY %s ", foreign,
					  fmtQualifiedDumpable(tbinfo));
	appendPQExpBuffer(delq, "DROP CONSTRAINT %s;\n",
					  fmtId(constrinfo->dobj.name));
}

void
dumpBabelPhysicalDatabaseACLs(Archive *fout)
{
	PQExpBuffer	query;

	if (!isBabelfishDatabase(fout) || fout->dopt->binary_upgrade)
		return;

	query = createPQExpBuffer();

	appendPQExpBuffer(query,
					"DO $$"
					"\nDECLARE"
					"\n	rolname TEXT;"
					"\n	original_name TEXT;"
					"\nBEGIN"
					"\n	SET LOCAL ROLE sysadmin;"
					"\n	FOR rolname, original_name IN ("
					"\n		SELECT a.rolname, a.orig_username FROM sys.babelfish_authid_user_ext a"
					"\n			WHERE orig_username IN ('dbo') AND"
					"\n			database_name NOT IN ('master', 'tempdb', 'msdb')");

	if (bbf_db_name)
		appendPQExpBuffer(query,
					"\n			 AND database_name = '%s')", escaped_bbf_db_name);

	appendPQExpBuffer(query,
					"\n	) LOOP"
					"\n		CASE WHEN original_name = 'dbo' THEN"
					"\n			EXECUTE format('GRANT CREATE, CONNECT, TEMPORARY ON DATABASE \"%%s\" TO \"%%s\"; ', CURRENT_DATABASE(), rolname);"
					"\n		END CASE;"
					"\n	END LOOP;"
					"\n	RESET ROLE;"
					"\nEND$$;\n\n");

	ArchiveEntry(fout, nilCatalogId, createDumpId(),
				 ARCHIVE_OPTS(.tag = "BABELFISHDATABASEACLS",
							  .description = "BABELFISHDATABASEACLS",
							  .section = SECTION_POST_DATA,
							  .createStmt = query->data));

	destroyPQExpBuffer(query);

	return;
}