/*-------------------------------------------------------------------------
 *
 * catalog.h
 *	  prototypes for functions in backend/catalog/catalog.c
 *
 *
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/catalog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef CATALOG_H
#define CATALOG_H

#include "catalog/pg_class.h"
#include "utils/relcache.h"


extern bool IsSystemRelation(Relation relation);
extern bool IsToastRelation(Relation relation);
extern bool IsCatalogRelation(Relation relation);

extern bool IsSystemClass(Oid relid, Form_pg_class reltuple);
extern bool IsToastClass(Form_pg_class reltuple);

extern bool IsCatalogRelationOid(Oid relid);

extern bool IsCatalogNamespace(Oid namespaceId);
extern bool IsToastNamespace(Oid namespaceId);

extern bool IsReservedName(const char *name);

extern bool IsSharedRelation(Oid relationId);

extern bool IsPinnedObject(Oid classId, Oid objectId);

extern Oid	GetNewOidWithIndex(Relation relation, Oid indexId,
							   AttrNumber oidcolumn);
extern RelFileNumber GetNewRelFileNumber(Oid reltablespace,
										 Relation pg_class,
										 char relpersistence,
										 bool override_temp);

typedef Oid (*GetNewTempObjectId_hook_type) (void);
extern GetNewTempObjectId_hook_type GetNewTempObjectId_hook;

typedef Oid (*GetNewTempOidWithIndex_hook_type) (Relation relation, Oid indexId, AttrNumber oidcolumn);
extern GetNewTempOidWithIndex_hook_type GetNewTempOidWithIndex_hook;

typedef bool (*IsExtendedCatalogHookType) (Oid relationId);
extern PGDLLEXPORT IsExtendedCatalogHookType IsExtendedCatalogHook;

typedef bool (*IsToastRelationHookType) (Relation relation);
extern PGDLLEXPORT IsToastRelationHookType IsToastRelationHook;

typedef bool (*IsToastClassHookType) (Form_pg_class pg_class_tup);
extern PGDLLEXPORT IsToastClassHookType IsToastClassHook;

#endif							/* CATALOG_H */
