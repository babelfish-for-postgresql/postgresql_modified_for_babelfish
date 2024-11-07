/*-------------------------------------------------------------------------
 *
 * Utility routines for babelfish objects
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/bin/pg_dump/dumpall_babel_utils.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include "catalog/pg_class_d.h"
#include "catalog/pg_proc_d.h"
#include "catalog/pg_type_d.h"
#include "common/logging.h"
#include "dumpall_babel_utils.h"
#include "fe_utils/string_utils.h"
#include "pg_backup_db.h"
#include "pg_backup_utils.h"
#include "pg_backup.h"
#include "pg_dump.h"
#include "pqexpbuffer.h"

#define exit_nicely(code) exit(code)

/* Babelfish virtual database to dump */
char *bbf_db_name = NULL;

/* enum to check if database to be dumped is a Babelfish Database */
typedef enum {
	NONE, OFF, ON
} babelfish_status;

static babelfish_status bbf_status = NONE;

static char default_bbf_roles[] = "('sysadmin', 'bbf_role_admin', "
								  "'master_dbo', 'master_db_owner', 'master_guest', "
								  "'msdb_dbo', 'msdb_db_owner', 'msdb_guest', "
								  "'tempdb_dbo', 'tempdb_db_owner', 'tempdb_guest')";

/*
 * Run a query, return the results, exit program on failure.
 */
static PGresult *
executeQuery(PGconn *conn, const char *query)
{
	PGresult   *res;

	pg_log_info("executing %s", query);

	res = PQexec(conn, query);
	if (!res ||
		PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		pg_log_error("query failed: %s", PQerrorMessage(conn));
		pg_log_error_detail("Query was: %s", query);
		PQfinish(conn);
		exit_nicely(1);
	}

	return res;
}

/*
 * getBabelfishInitUser
 * Returns initialize user of current Babelfish database
 * which is essentially same as owner of the database.
 */
static char *
getBabelfishInitUser(PGconn *conn)
{
	PQExpBuffer	qry;
	PGresult	*res;
	char    	*babel_init_user;

	qry = createPQExpBuffer();
	appendPQExpBufferStr(qry, "SELECT r.rolname FROM pg_roles r "
						 "INNER JOIN pg_database d ON r.oid = d.datdba "
						 "WHERE d.datname = current_database()");
	res = executeQuery(conn, qry->data);
	babel_init_user = pstrdup(PQgetvalue(res, 0, 0));
	PQclear(res);
	destroyPQExpBuffer(qry);

	return babel_init_user;
}

/*
 * isBabelfishDatabase:
 * returns true if current database has "babelfishpg_tsql"
 * extension installed, false otherwise.
 */
bool
isBabelfishDatabase(PGconn *conn)
{
	if(bbf_status == NONE)
	{
		PGresult *res;
		int		 ntups;
		res = executeQuery(conn, "SELECT extname FROM pg_extension WHERE extname = 'babelfishpg_tsql';");
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
 * dumpBabelRestoreChecks:
 * Dumps Babelfish specific pre-checks which get executed at the
 * beginning of restore to validate if restore can be performed
 * or not.
 */
void
dumpBabelRestoreChecks(FILE *OPF, PGconn *conn, int binary_upgrade)
{
	PGresult	*res;
	int     	source_server_version_num;
	char		*source_migration_mode;
	PQExpBuffer	qry;

	/* Skip if not Babelfish database or binary upgrade */
	if (!isBabelfishDatabase(conn) || binary_upgrade)
		return;

	/*
	 * Cross version Babelfish dump/restore is not yet supported so
	 * store the current server's version in the below procedure and
	 * add logic to fail the restore if the target server version
	 * differs from source server version.
	 */
	qry = createPQExpBuffer();
	res = executeQuery(conn, "SELECT setting::INT from pg_settings WHERE name = 'server_version_num';");
	source_server_version_num = atoi(PQgetvalue(res, 0, 0));

	/* SET babelfishpg_tsql.dump_restore GUC in the beginning */
	appendPQExpBufferStr(qry, "SET babelfishpg_tsql.dump_restore = TRUE;\n");

	/*
	 * Temporarily enable ON_ERROR_STOP so that whole restore script
	 * execution fails if the following do block raises an error.
	 */
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
	res =  executeQuery(conn, "SHOW babelfishpg_tsql.migration_mode");
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
	appendPQExpBufferStr(qry, "\\set ON_ERROR_STOP off\n");
	PQclear(res);

	fprintf(OPF, "%s", qry->data);

	destroyPQExpBuffer(qry);
	pfree(source_migration_mode);
}

/*
 * Returns query to fetch Babelfish users of specified physical/logical
 * database.
 * Note: We will dump only database users (not logins) in case of Babelfish
 * logical database dump.
 */
void
getBabelfishRolesQuery(PGconn *conn, PQExpBuffer buf, char *role_catalog, 
						bool drop_query, int binary_upgrade)
{
	if(!isBabelfishDatabase(conn) || binary_upgrade)
		return;

	resetPQExpBuffer(buf);
	appendPQExpBufferStr(buf, "WITH bbf_catalog AS (");
	/*
	 * Include logins only in case of Babelfish physical database dump.
	 * Note that we will not dump Babelfish initialize user as it might
	 * already be present on the target server.
	 */
	if (!bbf_db_name)
	{
		char *babel_init_user = getBabelfishInitUser(conn);
		appendPQExpBuffer(buf,
						  "SELECT rolname FROM sys.babelfish_authid_login_ext "
						  "WHERE rolname != '%s' " /* Do not dump Babelfish initialize user */
						  "UNION ",
						  babel_init_user);
		pfree(babel_init_user);
	}
	appendPQExpBufferStr(buf,
						 "SELECT rolname FROM sys.babelfish_authid_user_ext ");
	/* Only dump users of the specific logical database we are currently dumping. */
	if (bbf_db_name != NULL)
	{
		/*
		 * Get escaped bbf_db_name to handle special characters in it.
		 * 2*strlen+1 bytes are required for PQescapeString according to the documentation.
		 */
		char *escaped_bbf_db_name = pg_malloc(2 * strlen(bbf_db_name) + 1);

		PQescapeString(escaped_bbf_db_name, bbf_db_name, strlen(bbf_db_name));
		appendPQExpBuffer(buf, "WHERE database_name = '%s' ", escaped_bbf_db_name);
		pfree(escaped_bbf_db_name);
	}
	appendPQExpBuffer(buf, "), "
					  "bbf_roles AS (SELECT rc.* FROM %s rc INNER JOIN bbf_catalog bcat "
					  "ON rc.rolname = bcat.rolname) ", role_catalog);

	if (drop_query)
	{
		appendPQExpBuffer(buf,
						  "SELECT rolname "
						  "FROM bbf_roles "
						  "WHERE rolname !~ '^pg_' "
						  "AND rolname NOT IN %s "
						  "ORDER BY 1 ", default_bbf_roles);
	}
	else
	{
		appendPQExpBuffer(buf,
						  "SELECT oid, rolname, rolsuper, rolinherit, "
						  "rolcreaterole, rolcreatedb, "
						  "rolcanlogin, rolconnlimit, rolpassword, "
						  "rolvaliduntil, rolreplication, rolbypassrls, "
						  "pg_catalog.shobj_description(oid, '%s') as rolcomment, "
						  "rolname = current_user AS is_current_user "
						  "FROM bbf_roles "
						  "WHERE rolname !~ '^pg_' "
						  "AND rolname NOT IN %s "
						  "ORDER BY 2 ", role_catalog, default_bbf_roles);
	}
}

/*
 * Returns query to fetch all the roles, members and grantors of a
 * Babelfish  physical/logical database.
 */
void
getBabelfishRoleMembershipQuery(PGconn *conn, PQExpBuffer buf,
								char *role_catalog, int binary_upgrade)
{
	bool		dump_grant_options;
	int			server_version;

	if(!isBabelfishDatabase(conn) || binary_upgrade)
		return;

	server_version = PQserverVersion(conn);

	/*
	 * Previous versions of PostgreSQL also did not have a grant-level
	 * INHERIT option.
	 */
	dump_grant_options = (server_version >= 160000);

	resetPQExpBuffer(buf);
	appendPQExpBufferStr(buf, "WITH bbf_catalog AS (");
	/* Include all the logins only in case of Babelfish physical database dump. */
	if (!bbf_db_name)
	{
		char *babel_init_user = getBabelfishInitUser(conn);
		appendPQExpBuffer(buf,
						  "SELECT rolname FROM sys.babelfish_authid_login_ext "
						  "WHERE rolname != '%s' " /* Do not dump Babelfish initialize user */
						  "UNION ",
						  babel_init_user);
		pfree(babel_init_user);
	}
	/* Just include sysadmin role memberships in case of Babelfish logical database dump. */
	else
		appendPQExpBufferStr(buf,
							 "SELECT 'sysadmin' AS rolname UNION "
							 "SELECT 'bbf_role_admin' AS rolname UNION ");
	appendPQExpBuffer(buf,
					  "SELECT rolname FROM sys.babelfish_authid_user_ext ");
	/* Only dump users of the specific logical database we are currently dumping. */
	if (bbf_db_name != NULL)
	{
		/*
		 * Get escaped bbf_db_name to handle special characters in it.
		 * 2*strlen+1 bytes are required for PQescapeString according to the documentation.
		 */
		char *escaped_bbf_db_name = pg_malloc(2 * strlen(bbf_db_name) + 1);

		PQescapeString(escaped_bbf_db_name, bbf_db_name, strlen(bbf_db_name));
		appendPQExpBuffer(buf, "WHERE database_name = '%s' ", escaped_bbf_db_name);
		pfree(escaped_bbf_db_name);
	}
	appendPQExpBuffer(buf, "), "
					  "bbf_roles AS (SELECT rc.* FROM %s rc INNER JOIN bbf_catalog bcat "
					  "ON rc.rolname = bcat.rolname) ", role_catalog);

	appendPQExpBufferStr(buf, "SELECT ur.rolname AS role, "
						 "um.rolname AS member, "
						 "ug.oid AS grantorid, "
						 "ug.rolname AS grantor, "
						 "a.admin_option");

	if (dump_grant_options)
		appendPQExpBuffer(buf, ", a.inherit_option, a.set_option");
		
	appendPQExpBuffer(buf, " FROM pg_auth_members a "
						 "INNER JOIN bbf_roles ur on ur.oid = a.roleid "
						 "INNER JOIN bbf_roles um on um.oid = a.member "
						 "LEFT JOIN bbf_roles ug on ug.oid = a.grantor "
						 "WHERE NOT (ur.rolname ~ '^pg_' AND um.rolname ~ '^pg_') "
						 "AND NOT (ur.rolname IN %s AND um.rolname IN %s) "
						 "ORDER BY 1,2,4", default_bbf_roles, default_bbf_roles);
}
