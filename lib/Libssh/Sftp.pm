
package Libssh::Sftp;

use strict;
use warnings;
use Exporter qw(import);
use XSLoader;

our $VERSION = '0.2';

XSLoader::load('Libssh::Session', $VERSION);

use constant SSH_OK => 0;
use constant SSH_ERROR => -1;
use constant SSH_AGAIN => -2;
use constant SSH_EOF => -127;

use constant SSH_FX_OK => 0;
use constant SSH_FX_EOF => 1;
use constant SSH_FX_NO_SUCH_FILE => 2;
use constant SSH_FX_PERMISSION_DENIED => 3;
use constant SSH_FX_FAILURE => 4;
use constant SSH_FX_BAD_MESSAGE => 5;
use constant SSH_FX_NO_CONNECTION => 6;
use constant SSH_FX_CONNECTION_LOST => 7;
use constant SSH_FX_OP_UNSUPPORTED => 8;
use constant SSH_FX_INVALID_HANDLE => 9;
use constant SSH_FX_NO_SUCH_PATH => 10;
use constant SSH_FX_FILE_ALREADY_EXISTS => 11;
use constant SSH_FX_WRITE_PROTECT => 12;
use constant SSH_FX_NO_MEDIA => 13;

our @EXPORT_OK = qw(
SSH_FX_OK SSH_FX_EOF SSH_FX_NO_SUCH_FILE SSH_FX_PERMISSION_DENIED SSH_FX_FAILURE
SSH_FX_BAD_MESSAGE SSH_FX_NO_CONNECTION SSH_FX_CONNECTION_LOST SSH_FX_OP_UNSUPPORTED
SSH_FX_INVALID_HANDLE SSH_FX_NO_SUCH_PATH SSH_FX_FILE_ALREADY_EXISTS
SSH_FX_WRITE_PROTECT SSH_FX_NO_MEDIA
);
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

sub init {
    my ($self, %options) = @_;
    
    if (!defined($options{session}) || 
        ref($options{session}) ne 'Libssh::Session') {
        $self->set_err(msg => 'error allocating SFTP session: need to set session option');
        return SSH_ERROR;
    }
    my $session = $options{session}->get_session();
    if (!defined($session) || ref($session) ne 'ssh_session') {
        $self->set_err(msg => 'error allocating SFTP session: need to have a session init');
        return SSH_ERROR;
    }
    if ($options{session}->is_authenticated() == 0) {
        $self->set_err(msg => 'error allocating SFTP session: need to have a session authenticated');
        return SSH_ERROR;
    } 
    
    $self->{sftp_session} = sftp_new($session);
    if (!defined($self->{sftp_session})) {
        $self->set_err(msg => 'error allocating SFTP session: ' . $options{session}->get_error());
        return undef;
    }
        
    my $ret = sftp_init($self->{sftp_session});
    if ($ret != SSH_OK) {
        my $msg = 'error initializing SFTP session: ' . sftp_get_error($self->{sftp_session});
        sftp_free($self->{sftp_session});
        $self->{sftp_session} = undef;
        $self->set_err(msg => $msg);
        return $ret;
    }
        
    return SSH_OK;
}

sub new {
    my ($class, %options) = @_;
    my $self  = {};
    bless $self, $class;

    $self->{raise_error} = 0;
    $self->{print_error} = 0;
    $self->{stp_session} = undef;
    if (defined($options{session}) &&
        $self->init(session => $options{session}) != SSH_OK) {
        return undef;
    }
    
    return $self;
}

sub option_raiseerror {
    my ($self, %options) = @_;
    
    $self->{raise_error} = $options{value};
    return 0;
}

sub option_printerror {
    my ($self, %options) = @_;
    
    $self->{print_error} = $options{value};
    return 0;
}

sub options {
    my ($self, %options) = @_;

    foreach my $key (keys %options) {
        my $ret;

        my $func = $self->can("option_" . lc($key));
        if (defined($func)) {
            $ret = $func->($self, value => $options{$key});
        } else {
            $self->set_err(msg => sprintf("option '%s' is not supported", $key));
            return 0;
        }
        if ($ret != 0) {
            $self->set_err(msg => sprintf("option '%s' failed: %s", $key)) if ($ret < 0);
            return 0;
        }
    }
    
    return 1;
}

sub list_dir {
    my ($self, %options) = @_;
    
    if (!defined($self->{sftp_session})) {
        $self->set_err(msg => 'error: please attach the session');
        return SSH_ERROR;
    }
    
    
    return SSH_OK;
}

sub DESTROY {
    my ($self) = @_;

    if (defined($self->{sftp_session})) {        
        sftp_free($self->{sftp_session});
    }    
}

1;

__END__

=head1 NAME

Libssh::Sftp - Support for sftp via libssh.

=head1 SYNOPSIS

  !/usr/bin/perl

  use strict;
  use warnings;
  
  
  

=head1 DESCRIPTION

C<Libssh::Sftp> is a perl interface to the libssh (L<http://www.libssh.org>)
library. It doesn't support all the library. It's working in progress.

=head1 METHODS

=over 4

=item new

Create new Sftp object:

    my $sftp = Libssh::Sftp->new();

=item error ( )

Returns the last error message; returns undef if no error.

=back

=cut