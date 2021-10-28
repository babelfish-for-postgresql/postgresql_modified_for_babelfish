-- Applock test session #2
-- wait for some initialization of the other session
select pg_sleep(2);
select pg_advisory_lock(1);
select pg_advisory_unlock(1);

set babelfish_pg_tsql.sql_dialect = 'tsql';
\tsql on

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 1;
GO

-- Test #1: basic locking-out and timeout

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 2;
GO

-- timed out after waiting for 3 seconds
exec babel_getapplock_print_return @Resource = 'lock1', @LockMode = 'Exclusive', @LockOwner = 'SESSION', @LockTimeout = 1000;
GO

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 3;
go

-- lock acquired
exec babel_getapplock_print_return @Resource = 'lock1', @LockMode = 'Exclusive', @LockOwner = 'SESSION', @LockTimeout = 1000;
GO

exec babel_releaseapplock_print_return @Resource = 'lock1', @LockOwner = 'session';
GO

-- Parallel test #2: additional lock modes

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 4;
go

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 5;
go

-- IntentExclusive lock acquired while the other session is holding IntentShared on lock 1
exec babel_getapplock_print_return @Resource = 'lock1', @LockMode = 'IntentExclusive', @LockOwner = 'SESSION', @LockTimeout = 1000;
go

exec babel_releaseapplock_print_return @Resource = 'lock1', @LockOwner = 'SESSION';
go

-- Exclusive lock failed to acquire while the other session is holding IntentShared on lock 1
exec babel_getapplock_print_return @Resource = 'lock1', @LockMode = 'Exclusive', @LockOwner = 'SESSION', @LockTimeout = 1000;
go

exec babel_getapplock_print_return @Resource = 'lock2', @LockMode = 'Update', @LockOwner = 'SESSION', @LockTimeout = 1000;
go

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 6;
go

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 7;
go

exec babel_releaseapplock_print_return @Resource = 'lock2', @LockOwner = 'SESSION';
go

-- Parallel test #3: deadlock

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 8;
go

exec babel_getapplock_print_return @Resource = 'lock2', @LockMode = 'Exclusive', @LockOwner = 'SESSION', @LockTimeout = 1000;
go

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 9;
go

exec babel_getapplock_print_return @Resource = 'lock1', @LockMode = 'Exclusive', @LockOwner = 'SESSION', @LockTimeout = 60000;
go

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 10;
go

exec babel_releaseapplock_print_return @Resource = 'lock1', @LockOwner = 'SESSION';
go

exec babel_releaseapplock_print_return @Resource = 'lock2', @LockOwner = 'SESSION';
go

-- APPLOCK_TEST
insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 11;
GO

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 12;
GO

SELECT APPLOCK_TEST('public', 'lock1', 'Exclusive', 'session'); -- not grantable
go

SELECT APPLOCK_TEST('public', 'lock1', 'Shared', 'session'); -- grantable
go

insert into babel_applock_test_t1 values (1);
go
exec babel_applock_test_barrier 13;
GO
