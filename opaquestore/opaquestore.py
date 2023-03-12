#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, getpass
import pysodium, opaque, tomllib
from zxcvbn import zxcvbn
from SecureString import clearmem
from binascii import unhexlify, a2b_base64, b2a_base64
from dissononce.dh.x25519.keypair import KeyPair
from dissononce.dh.x25519.public import PublicKey
from opaquestore.noiseclient import NoiseWrapper
from opaquestore import server

#### consts ####

CREATE   =b'\x00'
GET      =b'\x66'
EXOP     =b'\xe0'

config = None

#### Helper fns ####

def encrypt_blob(sk, blob):
  # todo implement padding to hide length information
  nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
  ct = pysodium.crypto_secretbox(blob,nonce,sk)
  clearmem(sk)
  return nonce+ct

def decrypt_blob(sk, blob):
  nonce = blob[:pysodium.crypto_secretbox_NONCEBYTES]
  blob = blob[pysodium.crypto_secretbox_NONCEBYTES:]
  res = pysodium.crypto_secretbox_open(blob,nonce,sk)
  clearmem(sk)
  return res

def getpwd():
  if sys.stdin.isatty():
    return getpass.getpass("enter your password please: ").encode('utf8')
  else:
    return sys.stdin.buffer.readline().rstrip(b'\n')

def getcfg():
  paths=[
      # read global cfg
      '/etc/opaque-store/config',
      # update with per-user configs
      os.path.expanduser("~/.opaque-storerc"),
      # over-ride with local directory config
      os.path.expanduser("~/.config/opaque-store/config"),
      os.path.expanduser("opaque-store.cfg")
  ]
  config = dict()
  for path in paths:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        continue
    config.update(data)

  config['noise_key']=KeyPair.from_bytes(a2b_base64(config['noise_key']+'=='))
  config['server_pubkey']=PublicKey(a2b_base64(config['server_pubkey']+'=='))
  return config

#### OPs ####

def create(s, pwdU, keyid, data):
  ## wrap the IDs into an opaque.Ids struct:
  ids=opaque.Ids(keyid, f"{config['address']}:{config['port']}")

  sec, M = opaque.CreateRegistrationRequest(pwdU)
  s.sendall(CREATE+M)

  pub = s.read_pkt(0)
  #print("received pub:", pub.hex())

  rec, export_key = opaque.FinalizeRequest(sec, pub, ids)
  blob = encrypt_blob(export_key[:pysodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES], data)
  s.sendall(keyid)
  s.sendall(rec)
  s.sendall(blob)

  ret = s.read_pkt(0)

  return ret

def get(s, pwdU, keyid):
  # user initiates a credential request
  s.sendall(GET+keyid)
  pub, sec = opaque.CreateCredentialRequest(pwdU)
  s.sendall(pub)

  resp = s.read_pkt(0)
  ## user recovers its credentials from the servers response
  ids=opaque.Ids(keyid, f"{config['address']}:{config['port']}")
  sk, authU, export_key = opaque.RecoverCredentials(resp, sec, config.get('context',"opaque-store"), ids)
  clearmem(authU)
  clearmem(sk)

  data = s.read_pkt(0)
  blob = decrypt_blob(export_key[:pysodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES], data)
  clearmem(export_key)
  return blob

def delete(s,pwd):
  pass

def change(s):
  pass

def usage(params, help=False):
  print("usage: %s " % params[0])
  print("      %s server" % params[0])
  print("      echo -en 'password\ntoken2store' | %s create <keyid>" % params[0])
  print("                    echo -n 'password' | %s get <keyid>" % params[0])
  if help: sys.exit(0)
  sys.exit(100)

def test_pwd(pwd):
  q = zxcvbn(pwd.decode('utf8'))
  print("your %s%s (%s/4) master password can be online recovered in %s, and offline in %s, trying ~%s guesses" %
        ("★" * q['score'],
         "☆" * (4-q['score']),
         q['score'],
         q['crack_times_display']['online_throttling_100_per_hour'],
         q['crack_times_display']['offline_slow_hashing_1e4_per_second'],
         q['guesses']), file=sys.stderr)

#### main ####

def main(params=sys.argv):
  global config
  config = getcfg()

  if len(params) < 2: usage(params, True)
  cmd = None
  args = []
  if params[1] in ('help', '-h', '--help'):
    usage(params, True)
  elif params[1] == 'create':
    if len(params) != 3: usage(params)
    cmd = create
    pwd = getpwd()
    test_pwd(pwd)
    data = sys.stdin.buffer.read()
    args = (pwd, unhexlify(params[2]), data)
  elif params[1] == 'get':
    if len(params) != 3: usage(params)
    cmd = get
    pwd = getpwd()
    args = (pwd, unhexlify(params[2]))
  elif params[1] == 'server':
    return server.main()
  #elif params[1] == 'update':
  #  cmd = change
  #  args = () #(user, site, classes, syms, size, target)
  #elif params[1] == 'delete':
  #  if len(params) != 4: usage(params)
  #  cmd = delete
  #  args = (params[2], params[3])
  else:
    usage(params)

  error = None
  s = None
  pwd = ''
  try:
    s = NoiseWrapper.connect(config['address'], config['port'], config['noise_key'], config['server_pubkey'])
    ret = cmd(s, *args)
  except Exception as exc:
    error = exc
    ret = False
    raise # only for dbg
  clearmem(pwd)
  if s and s.fd.fileno() != -1: s.fd.close()

  if not ret:
    if not error:
      print("fail", file=sys.stderr)
      sys.exit(3) # error not handled by exception
    print(error, file=sys.stderr)
    sys.exit(1) # generic errors

  if cmd != delete:
    print(ret)
    sys.stdout.flush()
    clearmem(ret)
  elif ret != True:
    print("reached code that should not be reachable: ", ret)

if __name__ == '__main__':
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    raise # only for dbg
