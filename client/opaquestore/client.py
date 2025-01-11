#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, getpass, ssl, socket, struct
import pysodium, opaque, pyoprf
try:
  from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None
from SecureString import clearmem
from opaquestore.cfg import getcfg
from pyoprf.multiplexer import Multiplexer
from binascii import a2b_base64, b2a_base64
from itertools import zip_longest

#### consts ####

CREATE      =b'\x00'
UPDATE      =b'\x33'
GET_RTOKEN  =b'\x50'
GET         =b'\x66'
CHANGE_DKG  =b'\xa0'
CREATE_DKG  =b'\xf0'
UNLOCK      =b'\xf5'
DELETE      =b'\xff'

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

def split_by_n(iterable, n):
    return list(zip_longest(*[iter(iterable)]*n, fillvalue=''))

def getpwd():
  if sys.stdin.isatty():
    return getpass.getpass("please enter your password: ").encode('utf8')
  else:
    return sys.stdin.buffer.readline().rstrip(b'\n')

def processcfg(config):
  servers = config.get('servers',{})
  config = config.get('client',{})

  config['threshold'] = int(config.get('threshold') or "1")
  config['ts_epsilon'] = int(config.get('ts_epsilon') or "1200")

  for server in servers.values():
    try:
        server['ssl_cert'] = os.path.expanduser(server.get('ssl_cert')) # only for dev, production system should use proper certs!
    except TypeError: # ignore exception in case ssl_cert is not set, thus None is attempted to expand.
        server['ssl_cert'] = None

  if len(servers)>1:
      if config['threshold'] < 2:
          print('if you have multiple servers in your config, you must specify a threshold, which must be: len(servers) > threshold > 1 also')
          exit(1)
      if len(servers)<config['threshold']:
          print(f'threshold({config["threshold"]}) must be less than the number of servers({len(servers)}) in your config')
          exit(1)
  elif config['threshold'] > 1:
      print(f'threshold({config["threshold"]}) must be less than the number of servers({len(servers)}) in your config')
      exit(1)
  config['servers']=servers

  return config

def read_pkt(s,i,plen=None):
   res = []
   if plen is None:
     plen = s[i].read(2)
     if len(plen)!=2:
       raise ValueError
     plen = struct.unpack(">H", plen)[0]

   read = 0
   while read<plen and (len(res)==0 or len(res[-1])!=0):
     res.append(s[i].read(plen-read))
     read+=len(res[-1])

   if len(res[-1])==0 and read<plen:
     if b''.join(res) == b"\x00\x04fail":
       return
     raise ValueError(f"short read only {len(b''.join(res))} instead of expected {plen} bytes")
   return b''.join(res)

def send_pkt(s, msg, i=None):
  plen = struct.pack(">H", len(msg))
  if i is None:
    s.broadcast(plen+msg)
  else:
    s.send(i, plen+msg)

def opaque_session(s, pwdU, keyid, op, force=False):
  # user initiates a credential request
  ke1_0, sec_0 = opaque.CreateCredentialRequest_oprf(pwdU)
  secs=[]
  for i, peer in enumerate(s):
    pkid = pysodium.crypto_generichash(peer.name.encode('utf8') + keyid)

    ke1, sec = opaque.CreateCredentialRequest_ake(pwdU, sec_0, ke1_0)
    s.send(i, op+pkid+ke1)
    secs.append(sec)
  clearmem(sec_0)

  ke2s = s.gather(opaque.OPAQUE_SERVER_SESSION_LEN)
  attempts = dict([(i, struct.unpack(">i", a)[0]) for i, a in enumerate(s.gather(4)) if a is not None])

  missing = []
  for i, peer in enumerate(s):
    ke2 = ke2s[i]
    if ke2 is None:
      missing.append(i)
      print(f"oracle {i}: \"{peer.name} at {peer.address[0]}\" failed to load record or create opaque response", file=sys.stderr)

  if op == DELETE and len(missing)>0:
    raise ValueError(f'Delete operations require all servers to participate. Aborting. Use force-delete to delete from all available servers.')
  elif op == UPDATE and len(missing)>0:
    raise ValueError(f'Update operations require all servers to participate. Aborting. Use force-update to update all available servers.')
  elif (op == GET or force == True) and len(s) - len(missing) < config['threshold']:
    raise ValueError(f"Less than threshold ({config['threshold']}) number of servers available. Aborting.")

  indexes = bytes([i+1 for i,r in enumerate(ke2s) if r is not None])
  resps = b''.join(r for r in ke2s if r is not None)
  beta = opaque.CombineCredentialResponses(config['threshold'], len(indexes), indexes, resps)

  auths = []
  export_keys = []
  sks = []
  for i, peer in enumerate(s):
    ke2 = ke2s[i]
    ## user recovers its credentials from the servers response
    try:
      sk, authU, export_key = opaque.RecoverCredentials(ke2, secs[i], b"opaque-store", opaque.Ids(None, None), beta)
    except:
      print(f'{s[i].name} ({s[i].address[0]}): {attempts.get(i, '?')} attempts left', file=sys.stderr)
      raise ValueError(f"opaque failed, possibly wrong password?")
    clearmem(secs[i])
    if op in {GET_RTOKEN}:
      sks.append(sk)
    else:
      clearmem(sk)
    auths.append((i, authU))
    if op in {GET, UPDATE}:
      export_keys.append(export_key)
    else:
      clearmem(export_key)

  for i, authU in auths:
    s.send(i, authU)
    clearmem(authU)

  # TODO we are in trouble if op in UPDATE/DELETE but connection drops, or we are partly? unauthorized, can that happen?
  if op in {GET, UPDATE}:
    return export_keys
  if op in {GET_RTOKEN}:
    return sks

def dkg(m, threshold):
   n = len(m)

   # load peer long-term keys
   peer_lt_pks = []
   for name, server in config['servers'].items():
     with open(server.get('ltsigkey'),'rb') as fd:
       peer_lt_pk = fd.read()
       if(len(peer_lt_pk)!=pysodium.crypto_sign_PUBLICKEYBYTES):
         raise ValueError(f"long-term signature key for server {name} is of incorrect size")
       peer_lt_pks.append(peer_lt_pk)

   zero_shares = pyoprf.create_shares(bytes([0]*32), n, config['threshold'])

   tp, msg0 = pyoprf.tpdkg_start_tp(n, threshold, config['ts_epsilon'], "threshold opaque dkg create k", peer_lt_pks)
   m.broadcast(msg0)
   for i in range(n):
     m.send(i, zero_shares[i])

   while pyoprf.tpdkg_tp_not_done(tp):
     cur_step = pyoprf.tpdkg_tpstate_step(tp)
     ret, sizes = pyoprf.tpdkg_tp_input_sizes(tp)
     #print(f"step: {cur_step} {ret} {sizes}", file=sys.stderr)
     peer_msgs = []
     if ret:
       if sizes[0] > 0:
         peer_msgs_sizes = m.gather(2,n) #,debug=True)
         for i, (msize, size) in enumerate(zip(peer_msgs_sizes, sizes)):
           if struct.unpack(">H", msize)[0]!=size:
             raise ValueError(f"peer{i} ({m[i].name}{m[i].address}) sent invalid sized ({msize}) response, should be {size}")
         peer_msgs = m.gather(sizes[0],n) #,debug=True)
     else:
       peer_msgs = [read_pkt(m, i) if s>0 else b'' for i, s in enumerate(sizes)]
     for i, (pkt, size) in enumerate(zip(peer_msgs, sizes)):
       if(len(pkt)!=size):
         raise ValueError(f"peer{i} ({m[i].name}{m[i].address}) sent invalid sized ({len(pkt)}) response, should be {size}")
       #print(f"[{i}] received {pkt.hex()}", file=sys.stderr)
     msgs = b''.join(peer_msgs)

     try:
       out = pyoprf.tpdkg_tp_next(tp, msgs)
     except Exception as e:
       m.close()
       if pyoprf.tpdkg_tpstate_cheater_len(tp) > 0:
         cheaters, cheats = pyoprf.tpdkg_get_cheaters(tp)
         msg=[f"Warning during the distributed key generation the peers misbehaved: {sorted(cheaters)}"]
         for k, v in cheats:
           msg.append(f"\tmisbehaving peer: {k} was caught: {v}")
         msg = '\n'.join(msg)
         raise ValueError(msg)
       else:
         raise ValueError(f"{e} | tp step {cur_step}")
     #print(f"outlen: {len(out)}", file=sys.stderr)
     if(len(out)>0):
       for i in range(pyoprf.tpdkg_tpstate_n(tp)):
         msg = pyoprf.tpdkg_tp_peer_msg(tp, out, i)
         #print(f"sending({i} {m[i].name}({m[i].address}), {msg.hex()})", file=sys.stderr)
         send_pkt(m, msg, i)

#### OPs ####

def create(s, pwdU, keyid, data):
  secs=[]
  op = CREATE
  if config['threshold'] > 1:
    op = CREATE_DKG

  sec, req = opaque.CreateRegistrationRequest(pwdU)
  for i, peer in enumerate(s):
    # TODO TBA hashing the peername means that they cannot be changed
    # later maybe hash i instead?
    pkid = pysodium.crypto_generichash(peer.name.encode('utf8') + keyid)
    s.send(i, op+pkid+req)

  if op == CREATE_DKG:
    # conduct DKG
    dkg(s, config['threshold'])

  resps = s.gather(opaque.OPAQUE_REGISTER_PUBLIC_LEN)

  if op == CREATE_DKG:
    # combine shares into beta
    tmp = b''.join(resps)
    opaque.CombineRegistrationResponses(config['threshold'], len(resps), tmp)
    resps = split_by_n(tmp, opaque.OPAQUE_REGISTER_PUBLIC_LEN)

  recs=[]
  blobs=[]
  for i, peer in enumerate(s):
    pub = bytes(resps[i])
    if pub is None:
        raise ValueError("oracle failed to create registration response")
    #print("received pub:", len(pub), opaque.OPAQUE_REGISTER_PUBLIC_LEN, pub.hex())

    rec, export_key = opaque.FinalizeRequest(sec, pub, opaque.Ids(None, None))

    recs.append(rec)
    blob = encrypt_blob(export_key[:pysodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES], data)
    blobs.append(blob)

  for i, peer in enumerate(s):
    #print("send rec")
    s.send(i,recs[i])
    #print("send blob")
    send_pkt(s, blobs[i], i)

  for i, peer in enumerate(s):
    ret = read_pkt(s,i,2)
    if ret is None:
      raise ValueError("oracle failed to complete creation of record and/or blob")
    if ret != b'ok':
      raise ValueError("oracle failed to acknowledge success")
  return True

def get(s, pwdU, keyid):
  export_keys = opaque_session(s, pwdU, keyid, GET)

  blobs = []
  for i, peer in enumerate(s):
    data = read_pkt(s,i)
    if data is None:
        raise ValueError("unauthorized")
    blobs.append(decrypt_blob(export_keys[i][:pysodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES], data))
    clearmem(export_keys[i])
  blobs = {blob.decode('utf8') for blob in blobs}
  if len(blobs) != 1:
    raise ValueError("inconsistent blobs recovered")
  return list(blobs)[0]

def delete(s, pwdU, keyid, force=False):
  opaque_session(s, pwdU, keyid, DELETE, force)
  # todo ensure that all peers are connected!
  for i, peer in enumerate(s):
    ret = read_pkt(s,i,2)
    if ret is None:
      raise ValueError("unauthorized")
    if ret != b'ok':
      raise ValueError("oracle failed to acknowledge success")
  return True

def update(s, pwdU, keyid, data, force=False):
  export_keys = opaque_session(s, pwdU, keyid, UPDATE, force)
  # todo ensure that all peers are connected!
  blobs = []
  for i, peer in enumerate(s):
    blob = encrypt_blob(export_keys[i][:pysodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES], data)
    blobs.append(blob)

  for i, peer in enumerate(s):
    send_pkt(s, blobs[i], i)

  for i, peer in enumerate(s):
    ret = read_pkt(s,i,2)
    if ret is None:
      raise ValueError("unauthorized")
    if ret != b'ok':
      raise ValueError("oracle failed to acknowledge success")
  return True

def get_recovery_tokens(s, pwdU, keyid):
  sks = opaque_session(s, pwdU, keyid, GET_RTOKEN)

  tokens = []
  for i, peer in enumerate(s):
    data = read_pkt(s,i)
    if data is None:
        raise ValueError("unauthorized")
    tokens.append(decrypt_blob(sks[i][:pysodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES], data))
    clearmem(sks[i])
  return b2a_base64(b''.join(tokens)).strip().decode('utf8')

def unlock(s, pwdU, keyid):
  tokens = split_by_n(a2b_base64(pwdU), 16)
  for i, peer in enumerate(s):
    pkid = pysodium.crypto_generichash(peer.name.encode('utf8') + keyid)
    s.send(i, UNLOCK+pkid+bytes(tokens[i]))
  oks = s.gather(2)
  for i, ok in enumerate(oks):
    if ok != b'ok':
      raise ValueError(f"oracle ({s[i].name} @{s[i].address[0]}) failed to acknowledge success")
  return True

def genltsigkey(skpath=None, pkpath=None):
  if skpath is None:
    server_config = getcfg('opaque-stored')['server']

  if skpath is None:
    skpath = server_config['ltsigkey']

  if pkpath is None:
    pkpath = f"{skpath}.pub"

  if os.path.exists(skpath):
    print(f"{skpath} exists, refusing to overwrite, if you want to generate a new one, delete the old one first. aborting")
    return 1
  if os.path.exists(pkpath):
    print(f"{pkpath} exists, refusing to overwrite, if you want to generate a new one, delete the old one first. aborting")
    return 1

  pk, sk = pysodium.crypto_sign_keypair()
  with open(skpath, 'wb') as fd:
    fd.write(sk)
  with open(pkpath, 'wb') as fd:
    fd.write(pk)
  print(f"wrote secret-key to {skpath} and public-key to {pkpath}.")

def usage(params, help=False):
  print("usage: %s " % params[0])
  print("     %s genltsigkey [private-key path] [public-key path]" % params[0])
  print("      echo -en 'password\\ntoken2store' | %s create <keyid>" % params[0])
  print("                    echo -n 'password' | %s get <keyid>" % params[0])
  print("     echo -en 'password\\ntoken2update' | %s update <keyid>" % params[0])
  print("     echo -en 'password\\ntoken2update' | %s force-update <keyid>" % params[0])
  print("                    echo -n 'password' | %s delete <keyid>" % params[0])
  print("                    echo -n 'password' | %s force-delete <keyid>" % params[0])
  print("                    echo -n 'password' | %s recovery-tokens <keyid>" % params[0])
  print("              echo -n <recovery-token> | %s unlock <keyid>" % params[0])

  if help: sys.exit(0)
  sys.exit(100)

def test_pwd(pwd):
  if zxcvbn is None: return
  q = zxcvbn(pwd.decode('utf8'))
  print("your %s%s (%s/4) master password can be online recovered in %s, and offline in %s, trying ~%s guesses" %
        ("★" * q['score'],
         "☆" * (4-q['score']),
         q['score'],
         q['crack_times_display']['online_throttling_100_per_hour'],
         q['crack_times_display']['offline_slow_hashing_1e4_per_second'],
         q['guesses']), file=sys.stderr)

#### main ####

cmds = {'create': create,
        'get': get,
        'update': update,
        'force-update': update,
        'delete': delete,
        'force-delete': delete,
        'recovery-tokens': get_recovery_tokens,
        'unlock': unlock,
        'genltsigkey': genltsigkey,
        }

def main(params=sys.argv):
  #import ctypes
  #libc = ctypes.cdll.LoadLibrary('libc.so.6')
  #fdopen = libc.fdopen
  #log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
  #fdopen.restype = ctypes.c_void_p
  #log_file.value = fdopen(2, 'w')

  if len(params) < 2: usage(params, True)
  cmd = None
  args = []
  if params[1] in ('help', '-h', '--help'):
    usage(params, True)

  if params[1] not in cmds:
    usage(params)

  if params[1] == "genltsigkey":
      sys.exit(genltsigkey(*params[2:]))

  global config
  config = processcfg(getcfg('opaque-store'))

  if len(params) != 3: usage(params)
  pwd = getpwd()
  cmd =  cmds[params[1]]

  if params[1] == 'create':
    test_pwd(pwd)
    data = sys.stdin.buffer.read()
    args = (data,)
  elif params[1] in {'update', 'force-update'}:
    test_pwd(pwd)
    data = sys.stdin.buffer.read()
    if params[1] == 'force-update':
      args = (data,True)
    else:
      args = (data,)
  elif params[1] == 'force-delete':
    args = (True,)

  error = None
  s = None
  try:
    s = Multiplexer(config['servers'])
    s.connect()
    ret = cmd(s, pwd, pysodium.crypto_generichash(params[2], k=config['id_salt']), *args)
  except Exception as exc:
    error = exc
    ret = False
    raise # only for dbg
  clearmem(pwd)
  s.close()

  if not ret:
    if not error:
      print("fail", file=sys.stderr)
      sys.exit(3) # error not handled by exception
    print(error, file=sys.stderr)
    sys.exit(1) # generic errors

  if cmd in {get, get_recovery_tokens}:
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
