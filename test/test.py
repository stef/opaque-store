import unittest
from os import listdir, path
from shutil import rmtree
#from io import BytesIO
import sys, subprocess, time
from opaquestore import client
from opaquestore.cfg import getcfg
import tracemalloc
from pyoprf import multiplexer

# to get coverage, run
# PYTHONPATH=.. coverage run test.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory .

# disable the output the client

N = 3
pwd = 'asdf'
otherpwd = 'qwer'
keyid = b"keyid"
data = b"data1"

#class Input:
#  def __init__(self, txt = None):
#    if txt:
#      self.buffer = BytesIO('\n'.join((pwd, txt)).encode())
#    else:
#      self.buffer = BytesIO(pwd.encode())
#  def isatty(self):
#      return False
#  def close(self):
#    return

test_path = path.dirname(path.abspath(__file__))
client.config = client.processcfg(getcfg('opaque-store', test_path ))
for s in client.config['servers'].keys():
  client.config['servers'][s]['ssl_cert']='/'.join([test_path, client.config['servers'][s]['ssl_cert']])
  client.config['servers'][s]['ltsigkey']='/'.join([test_path, client.config['servers'][s]['ltsigkey']])

def connect(peers=None):
  if peers == None:
    peers = dict(tuple(client.config['servers'].items())[:N])
  m = multiplexer.Multiplexer(peers)
  m.connect()
  return m

class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
      cls._oracles = []
      for idx in range(N):
        log = open(f"{test_path}/servers/{idx}/log", "w")
        cls._oracles.append(
          (subprocess.Popen("../../../server/zig-out/bin/opaqueztore", cwd = f"{test_path}/servers/{idx}/", stdout=log, stderr=log, pass_fds=[log.fileno()]), log))
        log.close()
      time.sleep(0.8)

    @classmethod
    def tearDownClass(cls):
      for p, log in cls._oracles:
        p.kill()
        r = p.wait()
        log.close()
      time.sleep(0.4)

    def tearDown(self):
      for idx in range(N):
        ddir = f"{test_path}/servers/{idx}/data/"
        if not path.exists(ddir): continue
        for f in listdir(ddir):
          rmtree(ddir+f)

    def test_create(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

    def test_create_2x(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))
        with connect() as s:
            self.assertRaises(ValueError, client.create, s, pwd, keyid, data)

    def test_get(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))
        with connect() as s:
            res = client.get(s, pwd, keyid)
        self.assertIsInstance(res, str)
        self.assertEqual(res.encode('utf8'),data)

    def test_invalid_pwd(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        with connect() as s:
            self.assertRaises(ValueError, client.get, s, otherpwd, keyid)

    def test_invalid_keyid(self):
        with connect() as s:
            self.assertRaises(ValueError, client.get, s, pwd, keyid)

    def test_update(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))
        with connect() as s:
            res = client.get(s, pwd, keyid)
        self.assertIsInstance(res, str)
        self.assertEqual(res.encode('utf8'),data)

        updated = b"updated blob"
        with connect() as s:
            self.assertTrue(client.update(s, pwd, keyid, updated))

        with connect() as s:
            res1 = client.get(s, pwd, keyid)
        self.assertIsInstance(res1, str)
        self.assertEqual(res1.encode('utf8'),updated)

    def test_update_invalid_pwd(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))
        with connect() as s:
            res = client.get(s, pwd, keyid)
        self.assertIsInstance(res, str)
        self.assertEqual(res.encode('utf8'),data)

        updated = b"updated blob"
        with connect() as s:
            self.assertRaises(ValueError, client.update, s, otherpwd, keyid, updated)

    def test_delete(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        with connect() as s:
            self.assertTrue(client.delete(s, pwd, keyid))

        with connect() as s:
            self.assertRaises(ValueError, client.get, s, pwd, keyid)

    def test_delete_invalid_pwd(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        with connect() as s:
            self.assertRaises(ValueError, client.delete, s, otherpwd, keyid)

    def test_reset_fails(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        with connect() as s:
             self.assertRaises(ValueError, client.get, s, otherpwd, keyid)

        with connect() as s:
            res = client.get(s, pwd, keyid)
        self.assertIsInstance(res, str)
        self.assertEqual(res.encode('utf8'),data)

    def test_lock(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        # lock it
        for _ in range(3):
            with connect() as s:
                self.assertRaises(ValueError, client.get, s, otherpwd, keyid)

        # check that it is locked
        with connect() as s:
            self.assertRaises(ValueError, client.get, s, pwd, keyid)

    def test_get_rtoken(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        # get recovery token
        with connect() as s:
            rtoken = client.get_recovery_tokens(s, pwd, keyid)
        self.assertIsInstance(rtoken, str)

    def test_get_rtoken_invalid_pwd(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        # get recovery token
        with connect() as s:
            self.assertRaises(ValueError, client.get_recovery_tokens, s, otherpwd, keyid)

    def test_unlock(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        # get recovery token
        with connect() as s:
            rtoken = client.get_recovery_tokens(s, pwd, keyid)
        self.assertIsInstance(rtoken, str)

        # lock it
        for _ in range(3):
            with connect() as s:
                self.assertRaises(ValueError, client.get, s, otherpwd, keyid)

        # check that it is locked
        with connect() as s:
            self.assertRaises(ValueError, client.get, s, pwd, keyid)

        # unlock it
        with connect() as s:
          self.assertTrue(client.unlock(s, rtoken, keyid))

        # check success of unlocking
        with connect() as s:
            res = client.get(s, pwd, keyid)
        self.assertIsInstance(res, str)
        self.assertEqual(res.encode('utf8'),data)

    def test_unlock_invalid_rtoken(self):
        with connect() as s:
            self.assertTrue(client.create(s, pwd, keyid, data))

        # get recovery token
        with connect() as s:
            rtoken = client.get_recovery_tokens(s, pwd, keyid)
        self.assertIsInstance(rtoken, str)

        # lock it
        for _ in range(3):
            with connect() as s:
                self.assertRaises(ValueError, client.get, s, otherpwd, keyid)

        # check that it is locked
        with connect() as s:
            self.assertRaises(ValueError, client.get, s, pwd, keyid)

        # unlock it
        with connect() as s:
          self.assertRaises(ValueError, client.unlock, s, rtoken[::-1], keyid)

        # check success of unlocking
        with connect() as s:
            self.assertRaises(ValueError, client.get, s, pwd, keyid)

if __name__ == '__main__':
  unittest.main()
