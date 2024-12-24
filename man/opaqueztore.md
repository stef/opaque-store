# NAME

opaqueztore - OPAQUE-Store server

# SYNOPSIS

`opaqueztore`

# DESCRIPTION

OPAQUE-Store is a simple protocol that allows anyone to store encrypted blobs
of information online, with only a password needed to retrieve the information.
As the name implies it uses the OPAQUE protocol to do so. OPAQUE-Store uses the
`export_key` feature of OPAQUE to encrypt the data that is stored on the
OPAQUE-Storage server.

The server runs in the foreground and emits log messages to standard output. If
you want to run it as a daemon, you should deploy it using service supervision
tools such as s6, runit or daemontools.

When configured, the server should publish its long-term signing public-key so
that clients can use it in a threshold setup.

# SECURITY CONSIDERATIONS

You **should** back up your SSL key, `record_salt` configuration value,
ltsigkey and of course all blobs regularly.

# REPORTING BUGS

https://github.com/stef/opaque-store/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

`opaquestore(1)`, `opaque-stored.cfg(5)`
