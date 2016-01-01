#!/usr/bin/perl

use strict;
use warnings;
use Libssh::Session qw(:all);
use Libssh::Event;

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

my $fd = $session->get_fd();
print "== socket descriptor : " . $fd . "\n";

# wrong password
#if ($session->auth_password(password => $ssh_pass_wrong) != SSH_AUTH_SUCCESS) {
#    printf("auth issue: %s\n", $session->error(GetErrorSession => 1));
#}
if ($session->auth_password(password => $ssh_pass_good) != SSH_AUTH_SUCCESS) {
    printf("auth issue: %s\n", $session->error(GetErrorSession => 1));
    exit(1);
}

print "== authentification succeeded\n";

my $banner = $session->get_issue_banner();
printf("== server banner: %s\n", defined($banner) ? $banner : '-');

my $channel_id = $session->open_channel();
print "=== channel id = " . $channel_id . "\n";

my $channel_id2 = $session->open_channel();
print "=== channel id = " . $channel_id2 . "\n";

# Test event
#my $event = Libssh::Event->new();
#$event->add_session(session => $session);
#$event->add_channel_exit_status_callback(channel => $session->get_channel(channel_id => $channel_id));

$session->test_cmd(channel_ids => [ { id => $channel_id, cmd => 'ls -l' },
                                    { id => $channel_id2, cmd => 'sleep 20' },
                                  ]);

$channel_id = $session->open_channel();
print "=== channel id = " . $channel_id . "\n";
$channel_id = $session->open_channel();
print "=== channel id = " . $channel_id . "\n";

#printf("dopoll ret value = %s\n", $event->dopoll(timeout => 30000));

exit(0);
