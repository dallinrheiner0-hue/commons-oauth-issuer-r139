"""Two routes only. No OpenAPI, UI, lifespan operation, activation or issuer imports."""
import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from diagnostic import BINDING, RECEIPT_HASH, UNKNOWN, observe

ATTEMPT='r139-diagnostic-20260930-01'

def response(result,reason,started=None,finished=None):
    return {'protocol':'r139-diagnostic-v1','attempt_id':ATTEMPT,
      'initialization_id':BINDING['initialization_id'],'expected_receipt_sha256':RECEIPT_HASH,
      'classification':result,'reason':reason,'snapshot_started_utc':started,
      'snapshot_finished_utc':finished,'historical_outcome':'UNKNOWN'}

class Application:
    def __init__(self,dsn,binding,digest,deadline,connect,clock=time.time):
        if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest): raise ValueError('diagnostic digest required')
        self.dsn,self.binding,self.digest,self.deadline,self.connect,self.clock=dsn,binding,digest,deadline,connect,clock
        self.used=False; self.lock=threading.Lock()

    async def __call__(self,scope,receive,send):
        if scope['type']!='http': return
        status=404; data={'error':'not_found'}
        if scope.get('query_string',b''):
            status=400; data={'error':'query_not_allowed'}
        elif scope['method']=='GET' and scope['path']=='/healthz':
            status=200; data={'status':'diagnostic_only'}
        elif scope['method']=='GET' and scope['path']=='/diagnostic/state':
            headers=scope.get('headers',[])
            auth=[v for k,v in headers if k.lower()==b'authorization']
            body_headers=[v for k,v in headers if k.lower() in (b'transfer-encoding',b'content-length') and v!=b'0']
            valid=(len(auth)==1 and auth[0].startswith(b'Bearer ') and len(auth[0])==71 and
              hmac.compare_digest(hashlib.sha256(auth[0][7:]).hexdigest(),self.digest))
            if not valid:
                status=401; data={'error':'unauthorized'}
            elif body_headers:
                status=400; data={'error':'body_not_allowed'}
            elif not self.clock()<self.deadline:
                status=410; data=response(UNKNOWN,'EXPIRED')
            else:
                with self.lock:
                    claimed=not self.used
                    self.used=True
                if not claimed:
                    status=409; data=response(UNKNOWN,'ALREADY_CONSUMED_IN_PROCESS')
                else:
                    started=int(self.clock())
                    # Guard stays consumed if DB work or transport fails/cancels.
                    try:
                        result,reason=await asyncio.to_thread(observe,self.dsn,self.binding,self.connect)
                    except Exception:
                        result,reason=UNKNOWN,'OBSERVATION_UNCERTAIN'
                    status=200; data=response(result,reason,started,int(self.clock()))
        encoded=json.dumps(data,sort_keys=True,separators=(',',':')).encode()
        await send({'type':'http.response.start','status':status,'headers':[
          (b'content-type',b'application/json'),(b'cache-control',b'no-store'),
          (b'content-length',str(len(encoded)).encode())]})
        await send({'type':'http.response.body','body':encoded})

def create_app():
    import psycopg
    if os.environ.get('SYNTHETIC_OAUTH_ENABLED')!='false': raise ValueError('OAuth must remain disabled')
    # Public deployment gate is separately frozen; raw diagnostic token is never a server setting.
    from gate import DIGEST, DEADLINE
    if os.environ.get('DIAGNOSTIC_TOKEN_SHA256')!=DIGEST or os.environ.get('DIAGNOSTIC_DEADLINE')!=str(DEADLINE):
        raise ValueError('diagnostic gate mismatch')
    binding=json.loads(os.environ['DATABASE_BINDING'])
    if binding!=BINDING: raise ValueError('binding mismatch')
    return Application(os.environ['DATABASE_URL'],binding,DIGEST,DEADLINE,psycopg.connect)
