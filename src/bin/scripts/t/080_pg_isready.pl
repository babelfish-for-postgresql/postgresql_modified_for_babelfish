
# Copyright (c) 2021, PostgreSQL Global Development Group

use strict;
use warnings;

use PostgresNode;
use TestLib;
use Test::More tests => 10;

program_help_ok('pg_isready');
program_version_ok('pg_isready');
program_options_handling_ok('pg_isready');

my $node = get_new_node('main');
$node->init;

$node->command_fails(['pg_isready'], 'fails with no server running');

$node->start;

$node->command_ok(
	[ 'pg_isready', "--timeout=$TestLib::timeout_default" ],
	'succeeds with server running');
