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
 * Returns query to fetch all Babelfish users of specified logical database
 * and all the logins.
 * drop_query decides whether the qeury is to DROP the roles.
 */
void
getBabelfishRolesQuery(PQExpBuffer buf, char *role_catalog, bool drop_query)
{
	char *escaped_bbf_db_name;

	if (!bbf_db_name)
		return;

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
						  "WITH bbf_roles AS "
						  "(SELECT rolname from sys.babelfish_authid_user_ext "
						  "WHERE database_name = '%s' AND "
						  "rolname NOT IN ('master_dbo', 'master_db_owner', 'master_guest') "
						  "UNION SELECT rolname from sys.babelfish_authid_login_ext) "
						  "SELECT rc.rolname "
						  "FROM %s rc "
						  "INNER JOIN bbf_roles bc "
						  "ON rc.rolname = bc.rolname "
						  "WHERE rc.rolname !~ '^pg_' "
						  "ORDER BY 1", escaped_bbf_db_name, role_catalog);
	}
	else
	{
		printfPQExpBuffer(buf,
						  "WITH bbf_roles AS "
						  "(SELECT rolname from sys.babelfish_authid_user_ext "
						  "WHERE database_name = '%s' AND "
						  "rolname NOT IN ('master_dbo', 'master_db_owner', 'master_guest') "
						  "UNION SELECT rolname from sys.babelfish_authid_login_ext) "
						  "SELECT oid, rc.rolname, rolsuper, rolinherit, "
						  "rolcreaterole, rolcreatedb, "
						  "rolcanlogin, rolconnlimit, rolpassword, "
						  "rolvaliduntil, rolreplication, rolbypassrls, "
						  "pg_catalog.shobj_description(oid, '%s') as rolcomment, "
						  "rc.rolname = current_user AS is_current_user "
						  "FROM %s rc "
						  "INNER JOIN bbf_roles bc "
						  "ON rc.rolname = bc.rolname "
						  "WHERE rc.rolname !~ '^pg_' "
						  "ORDER BY 2", escaped_bbf_db_name, role_catalog, role_catalog);
	}
}

/*
 * Returns query to fetch al the roles, members and grantors related
 * to Babelfish users and logins.
 */
void
getBabelfishRoleMembershipQuery(PQExpBuffer buf, char *role_catalog)
{
	char *escaped_bbf_db_name;

	if (!bbf_db_name)
		return;

	/*
	 * Get escaped bbf_db_name to handle special characters in it.
	 * 2*strlen+1 bytes are required for PQescapeString according to the documentation.
	 */
	escaped_bbf_db_name = pg_malloc(2 * strlen(bbf_db_name) + 1);
	PQescapeString(escaped_bbf_db_name, bbf_db_name, strlen(bbf_db_name));

	resetPQExpBuffer(buf);
	printfPQExpBuffer(buf, "WITH bbf_roles AS "
					  "(SELECT rc.oid, rc.rolname FROM %s rc "
					  "INNER JOIN sys.babelfish_authid_user_ext bc "
					  "ON rc.rolname = bc.rolname WHERE bc.database_name = '%s' "
					  "UNION SELECT rc.oid, rc.rolname FROM %s rc "
					  "INNER JOIN sys.babelfish_authid_login_ext bc "
					  "ON rc.rolname = bc.rolname) "
					  "SELECT ur.rolname AS roleid, "
					  "um.rolname AS member, "
					  "a.admin_option, "
					  "ug.rolname AS grantor "
					  "FROM pg_auth_members a "
					  "INNER JOIN bbf_roles ur on ur.oid = a.roleid "
					  "INNER JOIN bbf_roles um on um.oid = a.member "
					  "LEFT JOIN bbf_roles ug on ug.oid = a.grantor "
					  "WHERE NOT (ur.rolname ~ '^pg_' AND um.rolname ~ '^pg_')"
					  "ORDER BY 1,2,3", role_catalog, escaped_bbf_db_name, role_catalog);
}
