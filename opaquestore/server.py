#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import socket, sys, os, datetime, binascii, os.path, traceback, struct
import pysodium, opaque, tomllib, select
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.interactive.XK import XKHandshakePattern
from dissononce.dh.x25519.keypair import KeyPair
from dissononce.dh.x25519.public import PublicKey
from binascii import a2b_base64, b2a_base64
import ctypes as c
from klutshnik.wrapper import thresholdmult, DKG, Evaluate, KEYID_SIZE, VERSION as KLUTSHNIK_VERSION
from klutshnik.utils import getcfg, split_by_n
from klutshnik.noiseclient import connect, gather

config = None

CREATE   =b'\x00'
GET      =b'\x66'
EXOP     =b'\xE0' # unimplemented

normal = "\033[38;5;%sm"
reset = "\033[0m"

oprflib = c.cdll.LoadLibrary(c.util.find_library('oprf') or
                             c.util.find_library('liboprf.so') or
                             c.util.find_library('liboprf') or
                             c.util.find_library('liboprf0'))
if not oprflib._name:
   raise ValueError('Unable to find liboprf')

@c.CFUNCTYPE(c.c_int, c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte))
def toprf_eval(keyid, alpha, beta):
  servers=config['servers']
  n = len(servers)
  t = config['threshold']
  keyid_ = bytes(keyid[:16])
  conns = connect(servers, Evaluate, t, n, keyid_, config['key'], config['authkey'], KLUTSHNIK_VERSION)

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
  # slightly simpler than klutshnik dkg
  #print("toprf_keygen(%d, %d)" % (k.value))
  n = len(config['servers'])
  threshold = config['threshold']
  keyid_ = pysodium.randombytes(KEYID_SIZE)
  conns = connect(config['servers'], DKG, threshold, n, keyid_, config['key'], config['authkey'], KLUTSHNIK_VERSION)

  responders=gather(conns, (pysodium.crypto_core_ristretto255_BYTES * threshold) + (33*n*2), n, lambda x: (x[:threshold*pysodium.crypto_core_ristretto255_BYTES], split_by_n(x[threshold*pysodium.crypto_core_ristretto255_BYTES:], 2*33)) )

  commitments = b''.join(responders[i][0] for i in range(n))
  for i in range(n):
      shares = b''.join([responders[j][1][i] for j in range(n)])
      msg = commitments + shares
      conns[i].sendall(msg)

  oks = gather(conns, 66, n)

  authtoken = conns[0].read_pkt(0)
  #setauthkey(keyid_,authtoken)
  print("authtoken for new key: ", b2a_base64(authtoken).decode('utf8').strip())
  for conn in conns:
    conn.fd.close()

  c.memmove(keyid, keyid_, len(keyid_))

def processcfg(config):
  config['noise_key']=KeyPair.from_bytes(binascii.a2b_base64(config['noise_key']+'=='))
  config['id_nonce']=binascii.a2b_base64(config['id_nonce']+'==')

  if 'servers' in config:
    print("found servers in config, switching to threshold opaque")
    oprflib.oprf_set_evalproxy(toprf_eval, toprf_keygen)
    config['servers'] = [(v.get('host',"localhost"),
                          v.get('port'),
                          PublicKey(a2b_base64(v['pubkey'])))
                         for k,v in config.get('servers',{}).items()]
    if not 'authkey' in config:
      raise ValueError("authkey for threshold setup missing config")
    config['authkey']=binascii.a2b_base64(config['authkey']+'==')

  with open(config['key'],'rb') as fd:
    config['key']=KeyPair.from_bytes(a2b_base64(fd.read()))

  return config

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
    config = processcfg(getcfg('opaque-stored'))

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

