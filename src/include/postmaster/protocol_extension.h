/*-------------------------------------------------------------------------
 *
 * protocol_extension.h
 *	  Exports and definitions for Loadable Protocol Extensions
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/postmaster/protocol_extension.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _PROTOCOL_EXTENSION_H
#define _PROTOCOL_EXTENSION_H

#include "libpq/libpq.h"

/*
 * hook function type for protocol extensions to register initialization
 */
typedef void (*listen_init_hook_type)(void);

/* Globals in postmaster.c */
extern	listen_init_hook_type listen_init_hook;

/* Functions in postmaster.c */
extern int	listen_have_free_slot(void);
extern void	listen_add_socket(pgsocket fd,
								ProtocolExtensionConfig *protocol_config);

extern int	libpq_accept(pgsocket server_fd, Port *port);
extern void	libpq_close(pgsocket server_fd);
extern void	libpq_init(void);
extern int	libpq_start(Port *port);
extern void	libpq_authenticate(Port *port, const char **username);
extern void	libpq_mainfunc(Port *port, int argc, char *arvg[])
								pg_attribute_noreturn();
extern void	libpq_send_message(ErrorData *edata);
extern void	libpq_send_cancel_key(int pid, int32 key);
extern void	libpq_comm_reset(void);
extern bool	libpq_is_reading_msg(void);
extern void	libpq_send_ready_for_query(CommandDest dest);
extern int	libpq_read_command(StringInfo inBuf);
extern void	libpq_end_command(QueryCompletion *qc, CommandDest dest);

#endif							/* _PROTOCOL_EXTENSION_H */
