#!/usr/bin/perl

use strict;
use warnings;
use Libssh::Session qw(:all);

my $session = Libssh::Session->new();
if (!$session->options(host => "127.0.0.1", port => 22)) {
    print $session->error() . "\n";
    exit(1);
}

if ($session->connect() != SSH_OK) {
    print $session->error() . "\n";
    exit(1);
}

print "=== ssh connection success ===\n";
exit(0);
