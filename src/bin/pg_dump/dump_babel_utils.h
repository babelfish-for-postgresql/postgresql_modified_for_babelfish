/*-------------------------------------------------------------------------
 *
 * Utility routines for babelfish objects
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/bin/pg_dump/dump_babel_utils.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef DUMP_BABEL_UTILS_H
#define DUMP_BABEL_UTILS_H

#include "pg_dump.h"
#include "pqexpbuffer.h"

/* PL/tsql table valued function types */
#define PLTSQL_TVFTYPE_NONE  0
#define PLTSQL_TVFTYPE_MSTVF 1
#define PLTSQL_TVFTYPE_ITVF  2

extern char *bbf_db_name;

extern void bbf_selectDumpableObject(DumpableObject *dobj, Archive *fout);
extern void fixTsqlDefaultExpr(Archive *fout, AttrDefInfo *attrDefInfo);
extern bool isBabelfishDatabase(Archive *fout);
extern void fixOprRegProc(Archive *fout, const OprInfo *oprinfo, const char *oprleft, const char *oprright, char **oprregproc);
extern void fixTsqlTableTypeDependency(Archive *fout, DumpableObject *func, DumpableObject *tabletype, char deptype);
extern bool isTsqlTableType(Archive *fout, const TableInfo *tbinfo);
extern int getTsqlTvfType(Archive *fout, const FuncInfo *finfo, char prokind, bool proretset);
extern void fixAttoptionsBbfOriginalName(Archive *fout, Oid relOid, const TableInfo *tbinfo, int idx);
extern void setOrResetPltsqlFuncRestoreGUCs(Archive *fout, PQExpBuffer q, const FuncInfo *finfo, char prokind, bool proretset, bool is_set);
extern void dumpBabelfishSpecificConfig(Archive *AH, const char *dbname, PQExpBuffer outbuf);
extern void updateExtConfigArray(Archive *fout, char ***extconfigarray, int nconfigitems);
extern char *babelfish_handle_view_def(Archive *fout, char *view_def);
extern void prepareForBabelfishDatabaseDump(Archive *fout, SimpleStringList *schema_include_patterns);
extern void setBabelfishDependenciesForLogicalDatabaseDump(Archive *fout);
extern void dumpBabelGUCs(Archive *fout);
extern void fixCursorForBbfCatalogTableData(Archive *fout, TableInfo *tbinfo, PQExpBuffer buf, int *nfields, char *attgenerated);
extern void fixCopyCommand(Archive *fout, PQExpBuffer copyBuf, TableInfo *tbinfo, bool isFrom);
extern bool hasSqlvariantColumn(TableInfo *tbinfo);
extern bool bbfIsDumpWithInsert(Archive *fout, TableInfo *tbinfo);
extern int fixCursorForBbfSqlvariantTableData(Archive *fout,
                                            TableInfo *tbinfo,
                                            PQExpBuffer query,
                                            int nfields,
                                            int **sqlvar_metdata_pos);
extern void castSqlvariantToBasetype(PGresult *res,
                                    Archive *fout,
                                    int row,
                                    int field,
                                    int sqlvariant_pos);
extern void dumpBabelRestoreChecks(Archive *fout);

#endif
