from dataclasses import dataclass
from urllib.parse import urlparse
@dataclass(frozen=True)
class Finding: header:str; status:str; detail:str
REQ={"strict-transport-security":"Transport security","content-security-policy":"Content injection protection","x-content-type-options":"MIME sniffing protection","referrer-policy":"Referrer control"}
def validate_url(u):
 p=urlparse(u)
 if p.scheme not in {"http","https"} or not p.netloc:raise ValueError("absolute http/https URL required")
def audit(headers,https=True):
 h={k.lower():v.strip() for k,v in headers.items()};out=[]
 for key,purpose in REQ.items():
  if key=="strict-transport-security" and not https:continue
  v=h.get(key)
  if not v:out.append(Finding(key,"missing",purpose))
  elif key=="x-content-type-options" and v.lower()!="nosniff":out.append(Finding(key,"weak","Expected nosniff"))
  elif key=="strict-transport-security" and "max-age=" not in v.lower():out.append(Finding(key,"weak","Missing max-age"))
  elif key=="content-security-policy" and "default-src" not in v.lower():out.append(Finding(key,"weak","Missing default-src"))
  else:out.append(Finding(key,"ok",purpose))
 return out
def score(fs):
 w={"ok":1,"weak":.5,"missing":0};return round(100*sum(w[f.status] for f in fs)/len(fs)) if fs else 100
def healthy(fs,minimum=75):return score(fs)>=minimum and not any(f.status=="missing" for f in fs)
