
# Copyright (c) 2021, PostgreSQL Global Development Group

# This module sets up a test server, for the SSL regression tests.
#
# The server is configured as follows:
#
# - SSL enabled, with the server certificate specified by argument to
#   switch_server_cert function.
# - ssl/root+client_ca.crt as the CA root for validating client certs.
# - reject non-SSL connections
# - a database called trustdb that lets anyone in
# - another database called certdb that uses certificate authentication, ie.
#   the client must present a valid certificate signed by the client CA
#
# The server is configured to only accept connections from localhost. If you
# want to run the client from another host, you'll have to configure that
# manually.
#
# Note: Someone running these test could have key or certificate files
# in their ~/.postgresql/, which would interfere with the tests.  The
# way to override that is to specify sslcert=invalid and/or
# sslrootcert=invalid if no actual certificate is used for a
# particular test.  libpq will ignore specifications that name
# nonexisting files.  (sslkey and sslcrl do not need to specified
# explicitly because an invalid sslcert or sslrootcert, respectively,
# causes those to be ignored.)

package SSLServer;

use strict;
use warnings;
use PostgresNode;
use TestLib;
use File::Basename;
use File::Copy;
use Test::More;

use Exporter 'import';
our @EXPORT = qw(
  configure_test_server_for_ssl
  switch_server_cert
);

# Force SSL tests nodes to begin in TCP mode. They won't work in Unix Socket
# mode and this way they will find a port to run on in a more robust way.
# Use an INIT block so it runs after the BEGIN block in TestLib.pm.

INIT { $TestLib::use_unix_sockets = 0; }

# Copy a set of files, taking into account wildcards
sub copy_files
{
	my $orig = shift;
	my $dest = shift;

	my @orig_files = glob $orig;
	foreach my $orig_file (@orig_files)
	{
		my $base_file = basename($orig_file);
		copy($orig_file, "$dest/$base_file")
		  or die "Could not copy $orig_file to $dest";
	}
	return;
}

# serverhost: what to put in listen_addresses, e.g. '127.0.0.1'
# servercidr: what to put in pg_hba.conf, e.g. '127.0.0.1/32'
sub configure_test_server_for_ssl
{
	my ($node, $serverhost, $servercidr, $authmethod, $password,
		$password_enc) = @_;

	my $pgdata = $node->data_dir;

	# Create test users and databases
	$node->psql('postgres', "CREATE USER ssltestuser");
	$node->psql('postgres', "CREATE USER md5testuser");
	$node->psql('postgres', "CREATE USER anotheruser");
	$node->psql('postgres', "CREATE USER yetanotheruser");
	$node->psql('postgres', "CREATE DATABASE trustdb");
	$node->psql('postgres', "CREATE DATABASE certdb");
	$node->psql('postgres', "CREATE DATABASE certdb_dn");
	$node->psql('postgres', "CREATE DATABASE certdb_dn_re");
	$node->psql('postgres', "CREATE DATABASE certdb_cn");
	$node->psql('postgres', "CREATE DATABASE verifydb");

	# Update password of each user as needed.
	if (defined($password))
	{
		$node->psql('postgres',
			"SET password_encryption='$password_enc'; ALTER USER ssltestuser PASSWORD '$password';"
		);
		# A special user that always has an md5-encrypted password
		$node->psql('postgres',
			"SET password_encryption='md5'; ALTER USER md5testuser PASSWORD '$password';"
		);
		$node->psql('postgres',
			"SET password_encryption='$password_enc'; ALTER USER anotheruser PASSWORD '$password';"
		);
	}

	# enable logging etc.
	open my $conf, '>>', "$pgdata/postgresql.conf";
	print $conf "fsync=off\n";
	print $conf "log_connections=on\n";
	print $conf "log_hostname=on\n";
	print $conf "listen_addresses='$serverhost'\n";
	print $conf "log_statement=all\n";

	# enable SSL and set up server key
	print $conf "include 'sslconfig.conf'\n";

	close $conf;

	# ssl configuration will be placed here
	open my $sslconf, '>', "$pgdata/sslconfig.conf";
	close $sslconf;

	# Copy all server certificates and keys, and client root cert, to the data dir
	copy_files("ssl/server-*.crt", $pgdata);
	copy_files("ssl/server-*.key", $pgdata);
	chmod(0600, glob "$pgdata/server-*.key") or die $!;
	copy_files("ssl/root+client_ca.crt", $pgdata);
	copy_files("ssl/root_ca.crt",        $pgdata);
	copy_files("ssl/root+client.crl",    $pgdata);
	mkdir("$pgdata/root+client-crldir");
	copy_files("ssl/root+client-crldir/*", "$pgdata/root+client-crldir/");

	# Stop and restart server to load new listen_addresses.
	$node->restart;

	# Change pg_hba after restart because hostssl requires ssl=on
	configure_hba_for_ssl($node, $servercidr, $authmethod);

	return;
}

# Change the configuration to use given server cert file, and reload
# the server so that the configuration takes effect.
sub switch_server_cert
{
	my $node     = $_[0];
	my $certfile = $_[1];
	my $cafile   = $_[2] || "root+client_ca";
	my $crlfile  = "root+client.crl";
	my $crldir;
	my $pgdata = $node->data_dir;

	# defaults to use crl file
	if (defined $_[3] || defined $_[4])
	{
		$crlfile = $_[3];
		$crldir  = $_[4];
	}

	open my $sslconf, '>', "$pgdata/sslconfig.conf";
	print $sslconf "ssl=on\n";
	print $sslconf "ssl_ca_file='$cafile.crt'\n";
	print $sslconf "ssl_cert_file='$certfile.crt'\n";
	print $sslconf "ssl_key_file='$certfile.key'\n";
	print $sslconf "ssl_crl_file='$crlfile'\n" if defined $crlfile;
	print $sslconf "ssl_crl_dir='$crldir'\n"   if defined $crldir;
	close $sslconf;

	$node->restart;
	return;
}

sub configure_hba_for_ssl
{
	my ($node, $servercidr, $authmethod) = @_;
	my $pgdata = $node->data_dir;

	# Only accept SSL connections from $servercidr. Our tests don't depend on this
	# but seems best to keep it as narrow as possible for security reasons.
	#
	# When connecting to certdb, also check the client certificate.
	open my $hba, '>', "$pgdata/pg_hba.conf";
	print $hba
	  "# TYPE  DATABASE        USER            ADDRESS                 METHOD             OPTIONS\n";
	print $hba
	  "hostssl trustdb         md5testuser     $servercidr            md5\n";
	print $hba
	  "hostssl trustdb         all             $servercidr            $authmethod\n";
	print $hba
	  "hostssl verifydb        ssltestuser     $servercidr            $authmethod        clientcert=verify-full\n";
	print $hba
	  "hostssl verifydb        anotheruser     $servercidr            $authmethod        clientcert=verify-full\n";
	print $hba
	  "hostssl verifydb        yetanotheruser  $servercidr            $authmethod        clientcert=verify-ca\n";
	print $hba
	  "hostssl certdb          all             $servercidr            cert\n";
	print $hba
	  "hostssl certdb_dn       all             $servercidr            cert clientname=DN map=dn\n",
	  "hostssl certdb_dn_re    all             $servercidr            cert clientname=DN map=dnre\n",
	  "hostssl certdb_cn       all             $servercidr            cert clientname=CN map=cn\n";
	close $hba;

	# Also set the ident maps. Note: fields with commas must be quoted
	open my $map, ">", "$pgdata/pg_ident.conf";
	print $map
	  "# MAPNAME       SYSTEM-USERNAME                           PG-USERNAME\n",
	  "dn             \"CN=ssltestuser-dn,OU=Testing,OU=Engineering,O=PGDG\"    ssltestuser\n",
	  "dnre           \"/^.*OU=Testing,.*\$\"                    ssltestuser\n",
	  "cn              ssltestuser-dn                            ssltestuser\n";

	return;
}

1;
