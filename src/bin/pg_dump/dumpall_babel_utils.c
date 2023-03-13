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

/*
 * Returns query to fetch default Babelfish users of specified logical database.
 * For a database DB, default roles will be: DB_dbo, DB_db_owner, DB_guest
 * drop_query decides whether the query is to DROP the roles.
 */
void
getBabelfishRolesQuery(PQExpBuffer buf, char *role_catalog, bool drop_query)
{
	char	*escaped_bbf_db_name;
	bool	is_builtin_db = false;

	if (!bbf_db_name)
		return;

	is_builtin_db = (pg_strcasecmp(bbf_db_name, "master") == 0 ||
			pg_strcasecmp(bbf_db_name, "tempdb") == 0 ||
			pg_strcasecmp(bbf_db_name, "msdb") == 0)
			? true : false;
	/*
	 * Get escaped bbf_db_name to handle special characters in it.
	 * 2*strlen+1 bytes are required for PQescapeString according to the documentation.
	 */
	escaped_bbf_db_name = pg_malloc(2 * strlen(bbf_db_name) + 1);
	PQescapeString(escaped_bbf_db_name, bbf_db_name, strlen(bbf_db_name));

	resetPQExpBuffer(buf);
	if (drop_query)
	{
		printfPQExpBuffer(buf,
						  "SELECT rolname "
						  "FROM %s "
						  "WHERE rolname !~ '^pg_' "
						  "AND rolname IN ('dbo', 'db_owner', '%s_dbo', '%s_db_owner', '%s_guest') "
						  "ORDER BY 1 ",
						  role_catalog, escaped_bbf_db_name,
						  escaped_bbf_db_name, escaped_bbf_db_name);

		/* builtin db users will already be present in the target server so no need to dump them */
		if (is_builtin_db)
			appendPQExpBufferStr(buf, "LIMIT 0");
	}
	else
	{
		printfPQExpBuffer(buf,
						  "SELECT oid, rolname, rolsuper, rolinherit, "
						  "rolcreaterole, rolcreatedb, "
						  "rolcanlogin, rolconnlimit, rolpassword, "
						  "rolvaliduntil, rolreplication, rolbypassrls, "
						  "pg_catalog.shobj_description(oid, '%s') as rolcomment, "
						  "rolname = current_user AS is_current_user "
						  "FROM %s "
						  "WHERE rolname !~ '^pg_' "
						  "AND rolname IN ('dbo', 'db_owner', '%s_dbo', '%s_db_owner', '%s_guest') "
						  "ORDER BY 2 ", role_catalog, role_catalog, escaped_bbf_db_name,
						  escaped_bbf_db_name, escaped_bbf_db_name);

		/* builtin db users will already be present in the target server so no need to dump them */
		if (is_builtin_db)
			appendPQExpBufferStr(buf, "LIMIT 0");
	}
}

/*
 * Returns query to fetch all the roles, members and grantors related
 * to Babelfish users of specified logical database.
 */
void
getBabelfishRoleMembershipQuery(PQExpBuffer buf, char *role_catalog)
{
	char	*escaped_bbf_db_name;

	if (!bbf_db_name)
		return;

	/*
	 * Get escaped bbf_db_name to handle special characters in it.
	 * 2*strlen+1 bytes are required for PQescapeString according to the documentation.
	 */
	escaped_bbf_db_name = pg_malloc(2 * strlen(bbf_db_name) + 1);
	PQescapeString(escaped_bbf_db_name, bbf_db_name, strlen(bbf_db_name));

	resetPQExpBuffer(buf);
	printfPQExpBuffer(buf,
					  "SELECT ur.rolname AS roleid, "
					  "um.rolname AS member, "
					  "a.admin_option, "
					  "ug.rolname AS grantor "
					  "FROM pg_auth_members a "
					  "LEFT JOIN %s ur on ur.oid = a.roleid "
					  "LEFT JOIN %s um on um.oid = a.member "
					  "LEFT JOIN %s ug on ug.oid = a.grantor "
					  "WHERE NOT (ur.rolname ~ '^pg_' AND um.rolname ~ '^pg_') "
					  "AND ur.rolname IN ('dbo', 'db_owner', '%s_dbo', '%s_db_owner', '%s_guest', 'sysadmin') "
					  "AND um.rolname IN ('dbo', 'db_owner', '%s_dbo', '%s_db_owner', '%s_guest', 'sysadmin') "
					  "AND ug.rolname IN ('dbo', 'db_owner', '%s_dbo', '%s_db_owner', '%s_guest', 'sysadmin') "
					  "ORDER BY 1,2,3",
					  role_catalog, role_catalog, role_catalog,
					  escaped_bbf_db_name, escaped_bbf_db_name, escaped_bbf_db_name,
					  escaped_bbf_db_name, escaped_bbf_db_name, escaped_bbf_db_name,
					  escaped_bbf_db_name, escaped_bbf_db_name, escaped_bbf_db_name);
}
