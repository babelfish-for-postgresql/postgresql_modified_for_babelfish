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

/* Babelfish virtual database to dump */
char *bbf_db_name = NULL;

/* enum to check if database to be dumped is a Babelfish Database */
typedef enum {
	NONE, OFF, ON
} babelfish_status;

static babelfish_status bbf_status = NONE;

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
		res = PQexec(conn, "SELECT extname FROM pg_extension WHERE extname = 'babelfishpg_tsql';");
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
	/* Include logins only in case of Babelfish physical database dump. */
	if (!bbf_db_name)
		appendPQExpBufferStr(buf,
							 "SELECT rolname FROM sys.babelfish_authid_login_ext UNION ");
	appendPQExpBuffer(buf,
					  "SELECT rolname FROM sys.babelfish_authid_user_ext), "
					  "bbf_roles AS (SELECT rc.* FROM %s rc INNER JOIN bbf_catalog bcat "
					  "ON rc.rolname = bcat.rolname) ", role_catalog);

	if (drop_query)
	{
		appendPQExpBufferStr(buf,
							 "SELECT rolname "
							 "FROM bbf_roles "
							 "WHERE rolname !~ '^pg_' "
							 "AND rolname NOT IN ('sysadmin', 'dbo', 'db_owner', "
							 "'master_dbo', 'master_db_owner', 'master_guest', "
							 "'msdb_dbo', 'msdb_db_owner', 'msdb_guest', "
							 "'tempdb_dbo', 'tempdb_db_owner', 'tempdb_guest') "
							 "ORDER BY 1 ");
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
						  "AND rolname NOT IN ('sysadmin', 'dbo', 'db_owner', "
						  "'master_dbo', 'master_db_owner', 'master_guest', "
						  "'msdb_dbo', 'msdb_db_owner', 'msdb_guest', "
						  "'tempdb_dbo', 'tempdb_db_owner', 'tempdb_guest') "
						  "ORDER BY 2 ", role_catalog);
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
	if(!isBabelfishDatabase(conn) || binary_upgrade)
		return;

	resetPQExpBuffer(buf);
	appendPQExpBufferStr(buf, "WITH bbf_catalog AS (");
	/* Include logins only in case of Babelfish physical database dump. */
	if (!bbf_db_name)
		appendPQExpBufferStr(buf,
							 "SELECT rolname FROM sys.babelfish_authid_login_ext UNION ");
	appendPQExpBuffer(buf,
					  "SELECT rolname FROM sys.babelfish_authid_user_ext), "
					  "bbf_roles AS (SELECT rc.* FROM %s rc INNER JOIN bbf_catalog bcat "
					  "ON rc.rolname = bcat.rolname) ", role_catalog);

	appendPQExpBuffer(buf, "SELECT ur.rolname AS roleid, "
					  "um.rolname AS member, "
					  "a.admin_option, "
					  "ug.rolname AS grantor "
					  "FROM pg_auth_members a "
					  "LEFT JOIN %s ur on ur.oid = a.roleid "
					  "INNER JOIN bbf_roles um on um.oid = a.member "
					  "LEFT JOIN %s ug on ug.oid = a.grantor "
					  "WHERE NOT (ur.rolname ~ '^pg_' AND um.rolname ~ '^pg_')"
					  "ORDER BY 1,2,3", role_catalog, role_catalog);
}
