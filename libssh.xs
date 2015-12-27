#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include <libssh/libssh.h> 

/* C functions */

MODULE = Libssh::Session		PACKAGE = Libssh::Session

# XS code

PROTOTYPES: ENABLED

ssh_session
ssh_new()
    CODE:
        RETVAL = ssh_new();
    OUTPUT: RETVAL

int
ssh_connect(ssh_session session)
    CODE:
        RETVAL = ssh_connect(session);
    OUTPUT: RETVAL

#
# ssh_options_set functions
#

int
ssh_options_set_host(ssh_session session, char *host)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_HOST, host);
    OUTPUT: RETVAL
    
int
ssh_options_set_port(ssh_session session, int port)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    OUTPUT: RETVAL

int
ssh_options_set_user(ssh_session session, char *user)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_USER, user);
    OUTPUT: RETVAL

int
ssh_options_set_timeout(ssh_session session, long timeout)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
    OUTPUT: RETVAL

#

const char *
ssh_get_error_from_session(ssh_session session)
    CODE:
        RETVAL = ssh_get_error(session);
    OUTPUT: RETVAL

int
ssh_is_connected(ssh_session session)
    CODE:
        RETVAL = ssh_is_connected(session);
    OUTPUT: RETVAL

NO_OUTPUT void
ssh_disconnect(ssh_session session)
    CODE:
        ssh_disconnect(session);

NO_OUTPUT void
ssh_free(ssh_session session)
    CODE:
        ssh_free(session);
