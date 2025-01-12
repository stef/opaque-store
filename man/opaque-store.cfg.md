# NAME

opaque-store.cfg - configuration for for OPAQUE-Store client `opaquestore`

# DESCRIPTION

This man page describes the format and various ways of configuring the
OPAQUE-Store client `opaquestore`.

The client looks for the configuration in the following files and order:

  - /etc/opaque-store/config
  - ~/.config/opaque-store/config
  - ~/.opaque-storerc
  - ./opaque-store.cfg

The configuration file format is TOML, see https://toml.io/ .

## `[Client]` SECTION

This section configures the general options of the client.

### `ID_SALT`

This value is used as an input to generating keyids for your records.
You must set/change this value, it ensures that your record ids are
unique. You must also make sure to not lose this value, if you do, you
lose access to your records. Has no default, must be set.

### THRESHOLD

This value sets the threshold for your server configuration. This
value is tightly dependent on the number of servers you have
configured in the `[servers]` section. If you have only one server
configured, this value must be also 1. This essentially disables
threshold operation.

In all other cases the number of servers must be at least one bigger
than the value of this variable. That means for the smallest threshold
setup, this value is 2 and you need three servers configured in the
`[servers]` section. The upper limit of this value 127, but it is
highly optimistic to run such large setups reliably.

### `TS_EPSILON`

The time in seconds a distributed keygen (DKG) protocol message is
considered fresh. anything older than this is considered invalid and
aborts a DKG. Higher values help with laggy links, lower values can
be fine if you have high-speed connections to all servers. Default: 1200s

### `[servers]` SECTION

This section contains the list of servers for the client. The number
of items in this list must be 1, if `threshold` is 1, otherwise this
section needs one more entry than the value of `threshold`.

Servers are in their own sections, with the following pattern:
`[servers.<name>]` Where name should be unique among all servers,
simple labels like opaqueztore1, opaqueztore2, etc. are totally
fine. These labels are important though, as they are used to generate
unique keyids for each server in the threshold setup, this makes the
records stored at the servers to be unlinkable between servers based
on their ids. So it is warmly recommended to back-up the names of the
servers, so you don't lose access to your records.

#### ADDRESS

This can be either an IPv4 or IPv6 address to listen on.

#### PORT

The port the server listens on.

#### `SSL_CERT`

This variable is a path pointing at a file containing a TLS certificate.
This is only needed for TLS certificates that are self-signed or otherwise not
in signed by CAs in your CA store.

#### LTSIGKEY

This variable is a path pointing at a file containing a public
long-term signing key of the server. You need to get this from the
operators of the OPAQUE-Store server. This value is only needed if you
run in a threshold setup.

## Threshold setup

The client config file, contains a `[servers]` section which lists all
servers you want to use in a threshold setup. Each server has an
`address`, `port` and `ltsigkey` variable that needs to be set
accordingly. In case the server runs with a self-signed certificate
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

You **SHOULD** back up your configuration file, most importantly the
value of `id_salt` and the names of the servers.

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
