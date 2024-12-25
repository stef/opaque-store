# OPAQUE-Store

OPAQUE-Store is a simple protocol that allows anyone to store
encrypted blobs of information online, with only a password needed to
retrieve the information. As the name implies it uses the OPAQUE
protocol to do so. OPAQUE-Store uses the `export_key` feature of
OPAQUE to encrypt the data that is stored on the OPAQUE-Storage
server.

You might want to read this blog-post on this topic and on more info:
`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

OPAQUE-Store goes beyond the original OPAQUE protocol as specified by
the IRTF/CFRG and also supports a threshold variant of OPAQUE. In a
threshold setup you have a number N of servers that all hold a share
of your secret and at least a threshold number T of these need to
cooperate to recover the secret. This provides extra robustness and
dillution of responsibility (losing a server is not the end of the
world!) while at the same time increases security, as an attacker now
has to compromise at least T servers to get access to some
information.

## Installation

opaquestore depends on https://github.com/stef/libopaque/ which in turn depends
on 
  - libsodium,
  - https://github.com/stef/pysodium available on pypi,
  - https://github.com/stef/liboprf, and
  - pyoprf (part of https://github.com/stef/liboprf) available on pypi.

When you have a working libopaque, a simple `pip install opaquestore`
should get you started.

## Configuration

Configuration will be looked for in the following order

  - /etc/opaque-store/config
  - ~/.config/opaque-store/config
  - ~/.opaque-storerc
  - ./opaque-store.cfg

For an example and documentation on the values in the config files
see: `opaque-store.cfg` for the client configuration, and - in case
you want to run your own server(s) - `opaque-stored.cfg` for the
server configuration.

Example configuration with inline comments about each value:

```
[client]
# you must change this value, it ensures that your record ids are
# unique you must also make sure to not lose this value, if you do,
# you lose access to your records.
id_salt="Please_MUST-be_changed! and backed up to something difficult to guess"
# the number of servers successfully participating in an
# operation. must be less than 129, but lower 1 digit number are
# probable the most robust.
threshold=2
# the time in seconds a distributed keygen (DKG) protocol message is
# considered fresh. anything older than this is considered invalid and
# aborts a DKG. Higher values help with laggy links, lower values can
# be fine if you have high-speed connections to all servers.
ts_epsilon=1200

# the list of servers, must be 1 item, if threshold is 1, or one more
# than threshold.
[servers]
[servers.zero]
# address of server
host="127.0.0.1"
# port where server is running
port=23000
# self-signed public key of the server
# - not needed for proper Lets Encrypt certs
ssl_cert = "/etc/opaquestore/zero/cert.pem"
ltsigkey="/etc/opaquestore/zero/zero.pub"

[servers.eins]
# address of server
host="127.0.0.1"
# port where server is running
port=23001
# public key of the server
ltsigkey="/etc/opaquestore/eins/eins.pub"

[servers.dva]
# address of server
host="127.0.0.1"
# port where server is running
port=23002
# public key of the server
ltsigkey="/etc/opaquestore/dva/dva.pub"
```

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

## Command-line usage and examples

It is warmly recommended to use pwdsphinx (https://github.com/stef/pwdsphinx)
as a front-end to opaquestore, since it handles passwords in a most secure
manner. If you want to use a different password manager, you can use the CLI
interface documented below.

### Passwords and Records

opaquestore takes the password always on the standard input. If you
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
people can guess your record ids.

### Store a new record

Storing a record needs 3 parameters:
 - the password, on standard input, terminated by a newline.
 - the record itself until the end of the standard input
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
not only those needed for matching the threshold, you want to update
the record on all servers not just some.


```sh
$ echo -en 'password\ntoken2update' | opaquestore update <keyId>
```

If you do not care if some servers will not be updated and you really
know what you are doing, you can use the alternative command
`force-update`, in this case the operation will succeed if at least
the threshold is matched. Note however if any of the servers that did
not participate in the forced update will participate in later
operations will corrupt later operations, so you might want to remove
those servers from your config.

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
hold the record, if your setup has a n-out-of-2*n setup could mean
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

If you run server, you need to generate some long-term signing keys if you want
to use this server in a threshold setup. If you don't provide the path to the
keys, the secret-key will be taken from the `ltsigkey` config value in your
`opaque-storaged` configuration, and the public-key will be the same as the
secret-key, but with a `.pub` extension.

```
$ opaquestore genltsigkey [secret-key path] [public-key path]
```
