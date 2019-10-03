#!/usr/bin/perl

use strict;
use warnings;
use Libssh::Session qw(:all);
use Time::HiRes qw (usleep);

my $ssh_host = "127.0.0.1";
my $ssh_port = 22;
my $ssh_user = "sshtest";
my $ssh_pass = "libsshtest";

my $NUM_PARALLEL_CONNECTIONS = 3;

sub init_session {
    my $session = Libssh::Session->new();
    if ($session->options(host => $ssh_host, port => $ssh_port, user => $ssh_user) != SSH_OK) {
        print $session->error() . "\n";
        exit(1);
    }

    if ($session->connect() != SSH_OK) {
        print $session->error() . "\n";
        exit(1);
    }

    if ($session->auth_publickey_auto() != SSH_AUTH_SUCCESS) {
        if ($session->auth_password(password => $ssh_pass) != SSH_AUTH_SUCCESS) {
            printf("auth issue: %s\n", $session->error(GetErrorSession => 1));
            exit(1);
        }
    }

    return $session;
}

sub init_nsessions {
    my ($num) = @_;
    die "You can't init less than one session." if ($num < 1);

    my @all_sessions = ();
    for (0 .. $num - 1) {
        my $session = init_session();
        push(@all_sessions, $session);
    }
    return @all_sessions;
}

my @all_sessions = init_nsessions($NUM_PARALLEL_CONNECTIONS);
my @all_channels = ();
my %has_returned = ();

my $sleep_seconds = 1;
my $session_index = 0;
for my $session (@all_sessions) {
    my $channel_id = $session->open_channel();
    my $channel = $session->get_channel(channel_id => $channel_id);
    push(@all_channels, $channel);

    print "== calling non-blocking 'sleep $sleep_seconds' for session with index '$session_index'\n";
    $session->set_blocking(blocking => 0);
    $session->channel_request_exec(channel => $channel, cmd => "sleep $sleep_seconds");
    $sleep_seconds += 1;
    $session_index++;
}

my $execution_time_leeway = $sleep_seconds + 2;
my $poll_interval_microseconds = 200000; # 0.2s
my $max_polls = $execution_time_leeway * 1000000 / $poll_interval_microseconds;
my $poll_count = 0;
while(1) {
    # check if timeout exceeded
    if ($poll_count > $max_polls) {
        die sprintf("Parallel calls failed to finish in %s seconds", $execution_time_leeway);
    }
    # check if every channel has already returned
    last if (scalar(keys(%has_returned)) == scalar(@all_sessions));

    # poll all channels again and check if there are any finished executions
    for my $i (0 .. scalar(@all_sessions) - 1) {
        next if (exists $has_returned{$i});
        my $rc = $all_sessions[$i]->channel_get_exit_status(channel => $all_channels[$i]);
        if ($rc != -1) {
            $has_returned{$i}++;
            print "    == session with index $i has finished execution with rc=$rc\n";
        }
    }
    usleep ($poll_interval_microseconds);
    $poll_count++;
}

print "== all sessions have finished execution\n";
exit(0);
