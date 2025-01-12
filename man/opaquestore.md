# NAME

opaquestore - command-line client for OPAQUE-Store

# SYNOPSIS

     `opaquestore` genltsigkey [private-key path] [public-key path]

      echo -en 'password\ntoken2store' | `opaquestore` create <keyid>

                    echo -n 'password' | `opaquestore` get <keyid>

     echo -en 'password\ntoken2update' | `opaquestore` update <keyid>

     echo -en 'password\ntoken2update' | `opaquestore` force-update <keyid>

                    echo -n 'password' | `opaquestore` delete <keyid>

                    echo -n 'password' | `opaquestore` force-delete <keyid>

                    echo -n 'password' | `opaquestore` recovery-tokens <keyid>

              echo -n <recovery-token> | `opaquestore` unlock <keyid>

# DESCRIPTION

OPAQUE-Store is a simple protocol that allows anyone to store
encrypted blobs of information online, with only a password needed to
retrieve the information. As the name implies it uses the OPAQUE
protocol to do so. OPAQUE-Store uses the `export_key` feature of
OPAQUE to encrypt the data that is stored on the OPAQUE-Storage
server, it then stores the encrypted data on the OPAQUE-Store server.

You might want to read this blog-post on this topic and on more info:
`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

OPAQUE-Store goes beyond the original OPAQUE protocol as specified by
the IRTF/CFRG (todo insert link to RFC when finally published) and
also supports a more secure and robust threshold variant of OPAQUE. In
a threshold setup you have a number N of servers that all hold a share
of your secret and at least a threshold number T of these need to
cooperate to recover the secret. This provides extra robustness and
dillution of responsibility (losing a server or two is not the end of
the world!) while at the same time increases security, as an attacker
now has to compromise at least T servers to get access to some
information.

## Configuration

For information on configuring `opaquestore`, see the man-page
`opaque-store.cfg(5)`.

## Command-line usage and examples

It is warmly recommended to use pwdsphinx (https://github.com/stef/pwdsphinx)
as a front-end to opaquestore, since it handles passwords in a most secure
manner. If you want to use a different password manager, you can use the CLI
interface documented below.

### Passwords and Records

`opaquestore` takes the password always on the standard input. If you
are creating or updating a record, the record itself is also expected
on the standard input. The password and the record - if required - are
separated by a newline character.

### KeyIds

KeyIds are the identifiers that you use to address your records, they
can be any kind of string. Internally this keyId is hashed using the
`id_salt` from the configurations `[client]` section into a unique
identifier. It is very warmly recommended to set this to some random
value, and to back this value up. As this salt is necessary to access
your records. If you use a commonly used salt (i.e. the default salt)
chances are high that there are collisions for record ids, and that
people can guess your record ids, and in the worst case lock these
down with repeated (wrong) password guesses.

## Command-line Operations

### Store a new record

Storing a record needs 3 parameters:
 - the password, on standard input, terminated by a newline, followed by
 - the record itself until the end of standard input
 - and a keyId with which you can reference and act on this record

```sh
$ echo -en 'password\ntoken2store' | opaquestore create <keyId>
```

Here is a contrived example:

```
echo -en "mypassword\!sMyV0ice\nmy secretty token data that i need to protect and store using opaque" | opaquestore create myfirstblob
```

In this example:
 - the password is "mypassword!sMyV0ice"
 - the record is: "my secretty token data that i need to protect and store using opaque"
 - and the keyId is "myfirstblob"

### Get a record

Retrieving a record has to parameters:

 - the password on standard input
 - the keyId as the 2nd parameter to `opaquestore`

```sh
$ echo -n 'password' | opaquestore get <keyId>
```

An example fetching the record created in the previous example:

```
echo -en "mypassword\!sMyV0ice" | opaquestore get myfirstblob
```

### Update a record

It is possible to update a record in place, it is essentially the same
as the creation of a record. It is important to note, that this
operation only succeeds, if all servers need to process this request,
not only those needed for matching the threshold. You want to update
the record on all servers not just some, otherwise later it might
cause (temporary) corruption when old and updated servers answers are
combined.


```sh
$ echo -en 'password\ntoken2update' | opaquestore update <keyId>
```

If you do not care if some servers will not be updated and you really
know what you are doing, you can use the alternative command
`force-update`, in this case the operation will succeed if at least
the threshold is matched. Note however if any of the servers that did
not participate in the forced update will participate in later
operations will corrupt later operations, so you might want to remove
those servers from your config, or block access to them.

```sh
$ echo -en 'password\ntoken2update' | opaquestore force-update <keyId>
```

### Delete a record

Deleting a record is very straight forward, you need your password and
keyId, and ensure that all servers that store this record will all be
available. The operation will fail if some servers are not available.

```sh
$ echo -n 'password' | opaquestore delete <keyId>
```

Similarly to the update operation there is also a forced delete
operation, which will succeed if at least the threshold is
matched. Servers not available during this forced delete will still
hold the record, if your setup has a `n-out-of-2*n` setup could mean
that you still have enough shares even after a forced-delete.

```sh
$ echo -n 'password' | opaquestore force-delete <keyId>
```

### Get some recovery-tokens

An attacker might be trying different passwords for your record, after
a certain amount of consecutive password failures (by default 3) the
server locks down the record. A locked record can only be unlocked
with a recovery-token. It is not possible to ask for recovery-tokens
when a record is already locked.

```sh
$ echo -n 'password' | opaquestore recovery-tokens <keyId>
```

### Unlock a locked record using a recovery token

If a record is locked, and you have a valid recovery-token you can
reset the failure counter:

```sh
$ echo -n <recovery-token> | opaquestore unlock <keyId>
```

### Generate long-term signature keys

This is a local operation only needed for setting up a new server.

If you set up a new server, you need to generate some long-term signing keys if
you want to use this server in a threshold setup. If you don't provide the path
to the keys, the secret-key will be taken from the `ltsigkey` config value in
your `opaque-storaged` configuration, and the public-key will be the same as
the secret-key, but with a `.pub` extension.

```
$ opaquestore genltsigkey [secret-key path] [public-key path]
```

# SECURITY CONSIDERATIONS

If you use OPAQUE-Store in a single-server setup, you need to use very strong
high-entropy passwords, as the operator of the server (or anyone who has access
to the server, maybe through a leak or hack)  is able to run offline bruteforce
attack against your password, and data. This threat is mitigated by using
OPAQUE-Store in a threshold setup where all of the 3rd party servers combined
fail to reach the threshold.

You **SHOULD** back up your configuration, especially the `id_salt` and the
names of the servers you are using, losing them means losing access to your data.

# REPORTING BUGS

https://github.com/stef/opaque-store/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

`opaque-store.cfg(5)`
