#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import socket, sys, os, datetime, binascii, os.path, traceback, struct
import pysodium, opaque, tomllib, select
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.interactive.XK import XKHandshakePattern
from dissononce.dh.x25519.keypair import KeyPair
from dissononce.dh.x25519.public import PublicKey
from binascii import a2b_base64, b2a_base64
from noiseclient import NoiseWrapper
import ctypes as c

config = None

CREATE   =b'\x00'
GET      =b'\x66'
EXOP     =b'\xE0' # unimplemented

DKG = 1
Evaluate  = 2

KEYID_SIZE = 16
KLUTSHNIK_VERSION = 1

normal = "\033[38;5;%sm"
reset = "\033[0m"

oprflib = c.cdll.LoadLibrary(c.util.find_library('oprf') or
                             c.util.find_library('liboprf.so') or
                             c.util.find_library('liboprf') or
                             c.util.find_library('liboprf0'))
if not oprflib._name:
   raise ValueError('Unable to find liboprf')

kmslib = c.cdll.LoadLibrary(c.util.find_library('kms') or
                            c.util.find_library('libkms.so') or
                            c.util.find_library('libkms') or
                            c.util.find_library('libkms0'))
if not kmslib._name:
   raise ValueError('Unable to find libkms')

def thresholdmult(threshold, parts):
   beta = c.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   if kmslib.toprf_thresholdmult(threshold, b''.join(parts[:threshold]), beta) != 0:
       raise ValueError
   return beta.raw

@c.CFUNCTYPE(c.c_int, c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte))
def toprf_eval(keyid, alpha, beta):
  servers=parse_servers(config)
  n = len(servers)
  t = config['threshold']
  keyid_ = bytes(keyid[:16])
  conns = connect(servers, Evaluate, t, n, keyid_)

  msg = bytes(alpha[:32]) + bytes(alpha[:32])
  for index,conn in enumerate(conns):
    # todo eval needs also a verifier, which we ignore here...
    conn.sendall(msg)

  # receive responses from tuokms_evaluate
  responders=gather(conns, 33*2, n, lambda pkt: (pkt[:33], pkt[33:]))

  xresps = tuple(responders[i][0] for i in range(n))

  # we only select the first t shares, should be rather random
  beta_ = thresholdmult(t, xresps)

  c.memmove(beta, beta_, len(beta_))

  return 0

@c.CFUNCTYPE(None, c.POINTER(c.c_ubyte))
def toprf_keygen(keyid):
  #print("toprf_keygen(%d, %d)" % (k.value))
  keyid_ = dkg(parse_servers(config), config['threshold'])
  c.memmove(keyid, keyid_, len(keyid_))

def parse_servers(config):
   res = []
   for k,v in config.get('servers',{}).items():
       host = v.get('host',"localhost")
       port = v.get('port')
       pubkey=PublicKey(a2b_base64(v['pubkey']))
       res.append((host, port, pubkey))
   return res

def getcfg():
  paths=[
      # read global cfg
      '/etc/opaque-stored/config',
      # update with per-user configs
      os.path.expanduser("~/.opaque-storedrc"),
      # over-ride with local directory config
      os.path.expanduser("~/.config/opaque-stored/config"),
      os.path.expanduser("opaque-stored.cfg")
  ]
  config = dict()
  for path in paths:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        continue
    config.update(data)

  config['noise_key']=KeyPair.from_bytes(binascii.a2b_base64(config['noise_key']+'=='))
  config['id_nonce']=binascii.a2b_base64(config['id_nonce']+'==')

  if 'servers' in config:
    print("found servers in config, switching to threshold opaque")
    oprflib.oprf_set_evalproxy(toprf_eval, toprf_keygen)

  with open(config['key'],'rb') as fd:
    config['key']=KeyPair.from_bytes(a2b_base64(fd.read()))

  return config

def split_by_n(obj, n):
  # src https://stackoverflow.com/questions/9475241/split-string-every-nth-character
  return [obj[i:i+n] for i in range(0, len(obj), n)]

def connect(servers, op, threshold, n, keyid):
   global config
   authkey = a2b_base64(config['authkey'])

   conns = []
   for host,port,pubkey in servers:
       fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       fd.settimeout(15)
       fd.connect((host, port))
       noised =NoiseWrapper(fd, config['key'], pubkey)
       conns.append(noised)

   for index,c in enumerate(conns):
      msg = b"%c%c%c%c%c%s" % (KLUTSHNIK_VERSION, op, index+1, threshold, n, keyid)
      c.sendall(msg)

   for c in conns:
      msg = authkey
      c.sendall(msg)

   return conns

def gather(conns, expectedmsglen, n, proc=None):
   responses={}
   while len(responses)!=n:
      fds={x.fd: (i, x) for i,x in enumerate(conns)}
      r, _,_ =select.select(fds.keys(),[],[],5)
      if not r: sys.exit(1)
      for fd in r:
         idx = fds[fd][0]
         if idx in responses:
            continue
         pkt = fds[fd][1].read_pkt(expectedmsglen)
         responses[idx]=pkt if not proc else proc(pkt)
   return responses

def dkg(servers,threshold):
   n = len(servers)
   keyid = pysodium.randombytes(KEYID_SIZE)
   conns = connect(servers, DKG, threshold, n, keyid)

   responders=gather(conns, (pysodium.crypto_core_ristretto255_BYTES * threshold) + (33*n*2), n, lambda x: (x[:threshold*pysodium.crypto_core_ristretto255_BYTES], split_by_n(x[threshold*pysodium.crypto_core_ristretto255_BYTES:], 2*33)) )

   commitments = b''.join(responders[i][0] for i in range(n))
   for i in range(n):
       shares = b''.join([responders[j][1][i] for j in range(n)])
       msg = commitments + shares
       conns[i].sendall(msg)

   oks = gather(conns, 66, n)
   # we ignore the response

   #shares = b''.join(oks[i] for i in range(n))
   #yc = c.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   #kmslib.tuokms_pubkey(n, threshold, shares, yc)

   authtoken = conns[0].read_pkt(0)
   #setauthkey(keyid,authtoken)
   print("authtoken for new key: ", b2a_base64(authtoken).decode('utf8').strip())
   for c in conns:
     c.fd.close()

   return keyid

class NoiseWrapperServer():
   def __init__(self, fd):
      global config
      self.fd = fd
      protocol = NoiseProtocolFactory().get_noise_protocol('Noise_XK_25519_ChaChaPoly_BLAKE2b')
      handshakestate = protocol.create_handshakestate()

      # initialize handshakestate objects
      handshakestate.initialize(XKHandshakePattern(), False, b'', s=config['noise_key'])

      # step 1, wait for initial message
      message_buffer = fd.recv(48)
      handshakestate.read_message(bytes(message_buffer), bytearray())

      # step 2, respond
      message_buffer = bytearray()
      handshakestate.write_message(b'', message_buffer)
      fd.sendall(message_buffer)

      # step 3, finish of
      message_buffer = fd.recv(64)
      self.state = handshakestate.read_message(bytes(message_buffer), bytearray())

   def send(self, data):
      return self.sendall(data)

   def close(self):
      self.fd.close()

   def shutdown(self, param):
      self.fd.shutdown(param)

   def sendall(self, pkt):
      ct = self.state[1].encrypt_with_ad(b'', pkt)
      msg = struct.pack(">H", len(ct)) + ct
      self.fd.sendall(msg)

   def read_pkt(self,size):
      res = []
      read = 0
      plen = self.fd.recv(2)
      if len(plen)!=2:
          raise ValueError
      plen = struct.unpack(">H", plen)[0]
      while read<plen or len(res[-1])==0:
        res.append(self.fd.recv(plen-read))
        read+=len(res[-1])
      return self.state[0].decrypt_with_ad(b'', b''.join(res))

def fail(s):
  if config['verbose']:
    traceback.print_stack()
    print('fail')
  s.send(b'\x00\x04fail') # plaintext :/
  s.shutdown(socket.SHUT_RDWR)
  s.close()
  os._exit(0)

def pop(obj, cnt):
  return obj[:cnt], obj[cnt:]

def load(keyid):
  rec_id = pysodium.crypto_generichash(keyid,config['id_nonce']).hex()
  rec_path = os.path.join(config['ots_path'], rec_id)
  rec, blob = None, None
  with open(os.path.join(rec_path,"rec"),'rb') as fd:
      rec = fd.read()
  with open(os.path.join(rec_path,"blob"),'rb') as fd:
      blob = fd.read()
  return rec, blob

def create(s, data):
  sec, pub = opaque.CreateRegistrationResponse(data)
  s.sendall(pub)

  keyid = s.read_pkt(0)
  rec0 = s.read_pkt(0)
  blob  = s.read_pkt(0)

  rec = opaque.StoreUserRecord(sec, rec0)

  rec_id = pysodium.crypto_generichash(keyid,config['id_nonce']).hex()
  rec_path = os.path.join(config['ots_path'], rec_id)
  if not os.path.exists(rec_path):
    os.makedirs(rec_path, 0o700, exist_ok=True)
  with open(os.path.join(rec_path,"rec"),'wb') as fd:
      fd.write(rec)
  with open(os.path.join(rec_path,"blob"),'wb') as fd:
      fd.write(blob)

  s.sendall(b'ok')

def get(s, keyid):
  rec, blob = load(keyid)
  pub = s.read_pkt(0)
  ## server responds to credential request
  ids=opaque.Ids(keyid, f"{config['address']}:{config['port']}")
  resp, _, _ = opaque.CreateCredentialResponse(pub, rec, ids, config.get('context',"opaque-store"))

  s.sendall(resp)
  s.sendall(blob)

def exop(s, keyid):
  # unimplemented
  # deoes a full OPAQUE and setups a protected channel to communicate any changes to the record
  rec, blob = load(keyid)
  pub = s.read_pkt(0)
  ## server responds to credential request
  ids=opaque.Ids(keyid, f"{config['address']}:{config['port']}")
  resp, sk, authU0 = opaque.CreateCredentialResponse(pub, rec, ids, config.get('context',"opaque-store"))

  s.sendall(resp)
  s.sendall(blob)

  # todo handle UPDATE, DELETE, CHANGE_PASSWD

def handler(conn):
  pkt = conn.read_pkt(0)
  if config['verbose']:
    print('Data received:',pkt.hex())
  op, pkt = pop(pkt,1)
  if op == CREATE:
    create(conn, pkt)
  elif op == GET:
    get(conn, pkt)
  elif op == EXOP: # unimplemented
    exop(conn, pkt)
  elif config['verbose']:
    print("unknown op: 0x%02x" % data[0])

  conn.close()
  os._exit(0)

def main():
    global config
    config = getcfg()

    socket.setdefaulttimeout(config['timeout'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((config['address'], config['port']))
    except socket.error as msg:
        print('Bind failed. Error Code : %s Message: %s' % (str(msg[0]), msg[1]))
        sys.exit()
    #Start listening on socket
    s.listen()
    kids = []
    try:
        # main loop
        while 1:
            #wait to accept a connection - blocking call
            try:
              conn, addr = s.accept()
            except socket.timeout:
              try:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid != 0:
                  print("remove pid", pid)
                  kids.remove(pid)
                continue
              except ChildProcessError:
                continue
            except:
              raise

            if config['verbose']:
                print('{} Connection from {}:{}'.format(datetime.datetime.now(), addr[0], addr[1]))

            while(len(kids)>config['max_kids']):
                pid, status = os.waitpid(0,0)
                kids.remove(pid)

            pid=os.fork()
            if pid==0:
              conn = NoiseWrapperServer(conn)
              try:
                handler(conn)
              except:
                print("fail")
                raise
              finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                conn.close()
              sys.exit(0)
            else:
                kids.append(pid)

            try:
              pid, status = os.waitpid(-1,os.WNOHANG)
              if pid!=0:
                 kids.remove(pid)
            except ChildProcessError: pass

    except KeyboardInterrupt:
        pass
    s.close()

if __name__ == '__main__':
  main()

