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

#include "dump_babel_utils.h"
#include "pg_dump.h"

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
