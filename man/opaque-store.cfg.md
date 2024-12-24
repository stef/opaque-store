# NAME

opaque-store.cfg - configuration for for OPAQUE-Store client `opaquestore`

# DESCRIPTION

The client looks for the configuration in the following files and order:

  - /etc/opaque-store/config
  - ~/.config/opaque-store/config
  - ~/.opaque-storerc
  - ./opaque-store.cfg

The configuration file format is TOML.

## `[Client]` SECTION

### `ID_SALT`

you must change this value, it ensures that your record ids are
unique you must also make sure to not lose this value, if you do,
you lose access to your records. Has no default, must be set.

### THRESHOLD

### `TS_EPSILON`

the time in seconds a distributed keygen (DKG) protocol message is
considered fresh. anything older than this is considered invalid and
aborts a DKG. Higher values help with laggy links, lower values can
be fine if you have high-speed connections to all servers. Default: 1200s

### `[servers]` SECTION

This section contains the list of servers for the client. The number of items
in this list must be 1, if `threshold` is 1, otherwise one more than `threshold`.

Servers are in their own sections, with the following pattern: `[servers.<name>]`
Where name should be ... TODO

#### ADDRESS

This can be either an IPv4 or IPv6 address to listen on.

#### PORT

The port the server listens on.

#### `SSL_CERT`

This variable is a path pointing at a file containing a TLS certificate.
This is only needed for TLS certificates that are self-signed or otherwise not
in the list of CAs.

#### LTSIGKEY

This variable is a path pointing at a file containing a public long-term
signing key of the server.


## Threshold setup

The client config file, contains a `[servers]` section which lists all
servers you want to use in a threshold setup. Each server has an
`address`, `port` and `ltsigkey` variable that needs to be set
accordingly.  In case your server runs with a self-signed certificate
there is a `ssl_cert` variable that can pin it to the correct cert.
It is also important to note, that the name of the server - which is
given after a dot in the `[servers.name]` sub-section title is also
used to generate record ids specific to that server. Thus once chosen,
it should not change, unless you want to lose access to the records on
that server. The name doesn't have to be unique by users, but should
be unique among all configured servers in this setup, this guarantees
that for a record each server has a different record it and thus makes
the records unlinkable across servers.

In the config files `[client]` section the `threshold` variable
specifies the threshold for the setup.

The minimum sane configuration for a threshold setup is `threshold=2` with at
least 3 servers listed. The maximum of servers is 128, but that is way too
many, a reasonable max is around 16 or so.

# FILES

  - /etc/opaque-store/config
  - ~/.config/opaque-store/config
  - ~/.opaque-storerc
  - ./opaque-store.cfg

# SECURITY CONSIDERATIONS

You **should** back up and encrypt your master key.

# REPORTING BUGS

https://github.com/stef/opaque-store/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

`opaquestore(1)`
