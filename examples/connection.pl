#!/usr/bin/perl

use strict;
use warnings;
use Libssh::Session qw(:all);

my $ssh_host = "127.0.0.1";
my $ssh_port = 22;
my $ssh_user = "root";
my $ssh_pass_wrong = "foo";
my $ssh_pass_good = "centreon";

my $session = Libssh::Session->new();
if (!$session->options(host => $ssh_host, port => $ssh_port, user => $ssh_user)) {
    print $session->error() . "\n";
    exit(1);
}

if ($session->connect() != SSH_OK) {
    print $session->error() . "\n";
    exit(1);
}

# wrong password
if ($session->auth_password(password => $ssh_pass_wrong) != SSH_AUTH_SUCCESS) {
    printf("auth issue: %s\n", $session->error(GetErrorSession => 1));
}
if ($session->auth_password(password => $ssh_pass_good) != SSH_AUTH_SUCCESS) {
    printf("auth issue: %s\n", $session->error(GetErrorSession => 1));
    exit(1);
}

print "== authentification succeeded\n";

my $banner = $session->get_issue_banner();
printf("== server banner: %s\n", defined($banner) ? $banner : '-');

exit(0);
