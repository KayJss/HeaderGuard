import unittest
from headerguard.core import *
class T(unittest.TestCase):
 def test_url(self):
  with self.assertRaises(ValueError):validate_url("/x")
 def test_full(self):
  f=audit({"Strict-Transport-Security":"max-age=1","Content-Security-Policy":"default-src 'self'","X-Content-Type-Options":"nosniff","Referrer-Policy":"same-origin"});self.assertEqual(score(f),100);self.assertTrue(healthy(f))
 def test_missing(self):self.assertFalse(healthy(audit({"X-Content-Type-Options":"nosniff"})))
 def test_weak(self):self.assertEqual(next(x for x in audit({"X-Content-Type-Options":"bad"},False) if x.header=="x-content-type-options").status,"weak")
 def test_http(self):self.assertNotIn("strict-transport-security",[x.header for x in audit({},False)])
 def test_threshold(self):self.assertTrue(healthy(audit({"Strict-Transport-Security":"max-age=1","Content-Security-Policy":"default-src 'self'","X-Content-Type-Options":"nosniff","Referrer-Policy":"same-origin"}),90))
if __name__=="__main__":unittest.main()
