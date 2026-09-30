import argparse,json
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from .core import *
def fetch(u,t):
 validate_url(u);req=Request(u,headers={"User-Agent":"HeaderGuard/0.1"})
 try:
  with urlopen(req,timeout=t) as x:return dict(x.headers.items())
 except HTTPError as e:return dict(e.headers.items())
 except URLError as e:raise RuntimeError(str(e.reason))
def main(argv=None):
 p=argparse.ArgumentParser(description="Audit HTTP response security headers.");p.add_argument("url");p.add_argument("--timeout",type=float,default=5);p.add_argument("--min-score",type=int,default=75);p.add_argument("--json",action="store_true");a=p.parse_args(argv)
 if not 0<=a.min_score<=100:p.error("--min-score must be 0..100")
 try:fs=audit(fetch(a.url,a.timeout),a.url.startswith("https://"))
 except (ValueError,RuntimeError) as e:p.error(str(e))
 data={"url":a.url,"score":score(fs),"healthy":healthy(fs,a.min_score),"findings":[f.__dict__ for f in fs]}
 if a.json:print(json.dumps(data,indent=2))
 else:
  print(f"Score: {data['score']}/100")
  for f in fs:print(f.status.upper(),f.header,f.detail)
 return 0 if data["healthy"] else 2
if __name__=="__main__":raise SystemExit(main())
