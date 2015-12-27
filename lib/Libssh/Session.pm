package Libssh::Session;

use strict;
use warnings;
use Exporter qw(import);
use XSLoader;

our $VERSION = '0.001';

XSLoader::load('Libssh::Session', $VERSION);

use constant SSH_OK => 0;
use constant SSH_ERROR => -1;
use constant SSH_AGAIN => -2;
use constant SSH_EOF => -127;

our @EXPORT_OK = qw(SSH_OK SSH_ERROR SSH_AGAIN SSH_EOF);
our @EXPORT = qw();
our %EXPORT_TAGS = ( 'all' => [ @EXPORT, @EXPORT_OK ] );

my $err;

sub set_err {
    my ($self, %options) = @_;
    
    $err = $options{msg};
    if ($self->{raise_error}) {
        die $err;
    }
    if ($self->{print_error}) {
        warn $err;
    }
}

sub error {
    my ($self, %options) = @_;
    
    return $err;
}

sub new {
    my ($class, %options) = @_;
    my $self  = {};
    bless $self, $class;

    $self->{raise_error} = 0;
    $self->{print_error} = 0;
    $self->{ssh_session} = ssh_new();
    if (!defined($self->{ssh_session})) {
        $self->set_err(msg => 'ssh_new failed: cannot init session');
        return undef;
    }
    return $self;
}

sub check_uint {
    my ($self, %options) = @_;
    
    if (!defined($options{value}) || $options{value} eq '') {
        $self->set_err(msg => sprintf("option '%s' failed: please set a value", $options{type}));
        return 1;
    }
    if ($options{value} !~ /^\d+$/) {
        $self->set_err(msg => sprintf("option '%s' failed: please set a positive number", $options{type}));
        return 1;
    }
    
    return 0;
}

sub option_host {
    my ($self, %options) = @_;
    
    return ssh_options_set_host($self->{ssh_session}, $options{value});
}

sub option_port {
    my ($self, %options) = @_;
    
    return 1 if ($self->check_uint(value => $options{value}, type => 'port'));
    return ssh_options_set_port($self->{ssh_session}, $options{value});
}

sub option_user {
    my ($self, %options) = @_;
    
    return ssh_options_set_user($self->{ssh_session}, $options{value});
}

sub option_timeout {
    my ($self, %options) = @_;
    
    return 1 if ($self->check_uint(value => $options{value}, type => 'timeout'));
    return ssh_options_set_timeout($self->{ssh_session}, $options{value});
}

sub options {
    my ($self, %options) = @_;

    foreach my $key (keys %options) {
        my $ret;

        my $func = $self->can("option_" . $key);
        if (defined($func)) {
            $ret = $func->($self, value => $options{$key});
        } else {
            $self->set_err(msg => sprintf("option '%s' is not supported", $key));
            return 0;
        }
        if ($ret != 0) {
            # error from libssh (< 0)
            $self->set_err(msg => sprintf("option '%s' failed: %s", $key, ssh_get_error_from_session($self->{ssh_session}))) if ($ret < 0);
            return 0;
        }
    }
    
    return 1;
}

sub connect {
    my ($self) = @_;

    my $ret = ssh_connect($self->{ssh_session});
    if ($ret != SSH_OK) {
        $self->set_err(msg => sprintf("connect failed: %s", ssh_get_error_from_session($self->{ssh_session})));
    }
    
    return $ret;
}

sub disconnect {
    my ($self) = @_;
    
    if (ssh_is_connected($self->{ssh_session}) == 1) {
        ssh_disconnect($self->{ssh_session});
    }
}

sub DESTROY {
    my ($self) = @_;

    if (defined($self->{ssh_session})) {
        $self->disconnect();
        ssh_free($self->{ssh_session});
    }
}

1;

__END__

=head1 NAME

Libssh::Session - Interface to the libssh library
