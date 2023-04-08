/*-------------------------------------------------------------------------
 *
 * parse_type.h
 *		handle type operations for parser
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/parser/parse_type.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PARSE_TYPE_H
#define PARSE_TYPE_H

#include "access/htup.h"
#include "parser/parse_node.h"


typedef HeapTuple Type;

extern Type LookupTypeName(ParseState *pstate, const TypeName *typeName,
						   int32 *typmod_p, bool missing_ok);
extern Type LookupTypeNameExtended(ParseState *pstate,
								   const TypeName *typeName, int32 *typmod_p,
								   bool temp_ok, bool missing_ok);
extern Oid	LookupTypeNameOid(ParseState *pstate, const TypeName *typeName,
							  bool missing_ok);
extern Type typenameType(ParseState *pstate, const TypeName *typeName,
						 int32 *typmod_p);
extern Oid	typenameTypeId(ParseState *pstate, const TypeName *typeName);
extern void typenameTypeIdAndMod(ParseState *pstate, const TypeName *typeName,
								 Oid *typeid_p, int32 *typmod_p);

extern char *TypeNameToString(const TypeName *typeName);
extern char *TypeNameListToString(List *typenames);

extern Oid	LookupCollation(ParseState *pstate, List *collnames, int location);
extern Oid	GetColumnDefCollation(ParseState *pstate, ColumnDef *coldef, Oid typeOid);

extern Type typeidType(Oid id);

extern Oid	typeTypeId(Type tp);
extern int16 typeLen(Type t);
extern bool typeByVal(Type t);
extern char *typeTypeName(Type t);
extern Oid	typeTypeRelid(Type typ);
extern Oid	typeTypeCollation(Type typ);
extern Datum stringTypeDatum(Type tp, char *string, int32 atttypmod);

extern Oid	typeidTypeRelid(Oid type_id);
extern Oid	typeOrDomainTypeRelid(Oid type_id);

extern TypeName *typeStringToTypeName(const char *str);
extern void parseTypeString(const char *str, Oid *typeid_p, int32 *typmod_p, bool missing_ok);

/* true if typeid is composite, or domain over composite, but not RECORD */
#define ISCOMPLEX(typeid) (typeOrDomainTypeRelid(typeid) != InvalidOid)

/* Hook to check/setup default typmod for sys.(N)(VAR)CHAR datatypes. */
typedef void (*check_or_set_default_typmod_hook_type)(TypeName * typeName, int32 *typmod, bool is_cast);
extern PGDLLIMPORT check_or_set_default_typmod_hook_type check_or_set_default_typmod_hook;

/*
 * Hook to check whether variable length datatypes like numeric, decimal, time, datetime2, datetimeoffset
 * are declared with permissible datalength at the time of table or stored procedure creation
 */
typedef void (*validate_var_datatype_scale_hook_type)(const TypeName *typeName, Type typ);
extern PGDLLIMPORT validate_var_datatype_scale_hook_type validate_var_datatype_scale_hook;

#endif							/* PARSE_TYPE_H */
