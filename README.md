# perl-libssh

I'm working on a Perl binding for the C libssh library : https://www.libssh.org/
It's in working progress. I'm a beginner with Perl XS.

Right now, you can:
* authenticate (password or pubkey) on a SSH server
* execute multiple commands (parallel)

[See code example](./example/connection.pl)