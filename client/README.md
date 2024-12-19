# OPAQUE-Store

This is a simple client-server system, which implements a simple online storage
of blobs, which can be recovered using only a password.

You might want to read this blogpost on this topic and on more info:
`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

## Installation

opaquestore depends on https://github.com/stef/libopaque/ which in turn
depends on libsodium and liboprf, and pyoprf.

When you have libopaque, a simple `pip install opaquestore` should get you started.

## Configfiles

For an example and documentation on the values in the config files
see: opaque-store.cfg for the client config, and opaque-stored.cfg for
the server config.

## Command-line usage and examples

### Passwords and Records

opaquestore takes the password always on the standard input. If you are
createing or updating a record, the record itself is also expected on the
standard input. The password and the optional record are separated by a newline
character.

### Keyids

Keyids are the identifiers that you use to address your records, they can be
anything.

### Store a new record

```sh
$ echo -en 'password\ntoken2store' | opaquestore create <keyid>
```

example:

```
echo -en "mypassword\!sMyV0ice\nmy secretty token data that i need to protect and store using opaque" | opaquestore create cfba1e747f706b542451a9d5404346f8
```

the password and the blob are expected on stdin, in this order,
seperated by a newline. The second parameter to the client is an ID
used to refer to the blob.

### Get a record

```sh
$ echo -n 'password' | opaquestore get <keyid>
```

example:

```
echo -en "mypassword\!sMyV0ice" | opaquestore get cfba1e747f706b542451a9d5404346f8
```
The password is again supplied on stdin, and the same ID as used for
creation is used as reference.

### Update a record

```sh
$ echo -en 'password\ntoken2update' | opaquestore update <keyid>
```

```sh
$ echo -en 'password\ntoken2update' | opaquestore force-update <keyid>
```

### Delete a record

```sh
$ echo -n 'password' | opaquestore delete <keyid>
```

```sh
$ echo -n 'password' | opaquestore force-delete <keyid>
```

### Get some recovery-tokens

```sh
$ echo -n 'password' | opaquestore recovery-tokens <keyid>
```

### Unlock a locked record using a recovery token

```sh
$ echo -n <recovery-token> | opaquestore unlock <keyid>
```

### Generate long-term signature keys

If you run server, you need to generate some long-term signing keys if you want
to use this server in a threshold setup. If you don't provide the path to the
keys, the secret-key will be taken from the `ltsigkey` config value in your
opaque-storaged configuration, and the public-key will be the same as the
secret-key, but with a `.pub` extension.

```
$ opaquestore genltsigkey [secret-key path] [public-key path]
```
