#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include <errno.h>
#include <libssh/libssh.h>
#include "channel.h"

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

socket_t
ssh_get_fd(ssh_session session)
    CODE:
        RETVAL = ssh_get_fd(session);
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

int
ssh_options_set_stricthostkeycheck(ssh_session session, int value)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &value);
    OUTPUT: RETVAL

int
ssh_options_set_ssh_dir(ssh_session session, char *ssh_dir)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_SSH_DIR, ssh_dir);
    OUTPUT: RETVAL

int
ssh_options_set_knownhosts(ssh_session session, char *knownhosts)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts);
    OUTPUT: RETVAL

int
ssh_options_set_log_verbosity(ssh_session session, int verbosity)
    CODE:
        RETVAL = ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    OUTPUT: RETVAL

#
# ssh auth
#

int
ssh_userauth_password(ssh_session session, char *password)
    CODE:
        RETVAL = ssh_userauth_password(session, NULL, password);
    OUTPUT: RETVAL

int
ssh_userauth_none(ssh_session session)
    CODE:
        RETVAL = ssh_userauth_none(session, NULL);
    OUTPUT: RETVAL

char *
ssh_get_issue_banner(ssh_session session)
    CODE:
        RETVAL = ssh_get_issue_banner(session);
    OUTPUT: RETVAL

#

int
ssh_is_server_known(ssh_session session)
    CODE:
        RETVAL = ssh_is_server_known(session);
    OUTPUT: RETVAL

ssh_key 
ssh_get_publickey(ssh_session session)
    CODE:
        ssh_key key;
        int success;
        
        RETVAL = NULL;
        success = ssh_get_publickey(session, &key);
        if (success == SSH_OK) {
            RETVAL = key;
        }
    OUTPUT: RETVAL
    
SV *
ssh_get_publickey_hash(ssh_key key, int type)
    CODE:
        SV *ret;
        unsigned char *hash;
        size_t hlen;
        int success;

        success = ssh_get_publickey_hash(key, type, &hash, &hlen);

        ret = &PL_sv_undef;
        
        if (success == 0) {
            ret = newSVpv((char *)hash, strlen((char *)hash));
            ssh_clean_pubkey_hash(&hash);
        }
        RETVAL = ret;
    OUTPUT: RETVAL

SV *
ssh_get_hexa(unsigned char *what)
    CODE:
        SV *ret;
        char *str;

        str = ssh_get_hexa(what, strlen((char *)what));
        ret = newSVpv(str, strlen(str));
        ssh_string_free_char(str);
        RETVAL = ret;
    OUTPUT: RETVAL

int
ssh_write_knownhost(ssh_session session)
    CODE:
        RETVAL = ssh_write_knownhost(session);
    OUTPUT: RETVAL

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
    
NO_OUTPUT void
ssh_key_free(ssh_key key)
    CODE:
        ssh_key_free(key);

#
# channel functions
#

ssh_channel
ssh_channel_new(ssh_session session)
    CODE:
        RETVAL = ssh_channel_new(session);
    OUTPUT: RETVAL

int
ssh_channel_open_session(ssh_channel channel)
    CODE:
        RETVAL = ssh_channel_open_session(channel);
    OUTPUT: RETVAL

NO_OUTPUT void
ssh_channel_free(ssh_channel channel)
    CODE:
        ssh_channel_free(channel);

int
ssh_channel_close(ssh_channel channel)
    CODE:
        RETVAL = ssh_channel_close(channel);
    OUTPUT: RETVAL

int
ssh_channel_send_eof(ssh_channel channel)
    CODE:
        RETVAL = ssh_channel_send_eof(channel);
    OUTPUT: RETVAL

int
ssh_channel_is_eof(ssh_channel channel)
    CODE:
        RETVAL = ssh_channel_is_eof(channel);
    OUTPUT: RETVAL

char *
ssh_channel_get_id(ssh_channel channel)
    CODE:
        char str[1024];
        
        sprintf(str, "%i:%i", channel->local_channel, channel->remote_channel);
        RETVAL = str;
    OUTPUT: RETVAL

char *
get_strerror()
    CODE:
        RETVAL = strerror(errno);
    OUTPUT: RETVAL