"""Dormant-by-default synthetic issuer. No startup writes, no automatic recovery."""
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import serialization
from starlette.responses import JSONResponse
from oauth import Config, Issuer, Reject, digest
from state import Database
from http_oauth import app_for

class Application:
    def __init__(self,db,origin,operator_digest,operator_deadline,issuer=None,clock=time.time):
        p=urlsplit(origin)
        if p.scheme!='https' or p.path or p.query or p.fragment or p.username or p.password or not p.hostname: raise Reject('ORIGIN')
        if len(operator_digest)!=64 or any(c not in '0123456789abcdef' for c in operator_digest): raise Reject('OPERATOR_DIGEST')
        if type(operator_deadline) is not int or not 0<operator_deadline<=clock()+86400: raise Reject('OPERATOR_WINDOW')
        self.operator_deadline,self.clock=operator_deadline,clock
        self.db,self.origin,self.operator_digest,self.issuer=db,origin,operator_digest,issuer
        self.oauth=app_for(issuer) if issuer else None

    async def __call__(self,scope,receive,send):
        if scope['type']!='http': return
        headers=scope.get('headers',[])
        def one(name):
            values=[v.decode('latin1') for k,v in headers if k.lower()==name]
            return values[0] if len(values)==1 else ''
        status=400; result={'error':'invalid_request'}
        try:
            # Render terminates TLS. Exactly one HTTPS proxy header and pinned Host.
            # Uvicorn proxy inference is disabled. Hosted edge overwriting remains a live gate.
            if one(b'host')!=urlsplit(self.origin).netloc or one(b'x-forwarded-proto')!='https': raise Reject('INGRESS')
            path=scope['path']; method=scope['method']
            if path=='/healthz' and method=='GET':
                result={'alive':True,'synthetic_only':True};status=200
            elif path in ('/initialize','/activate','/status'):
                auth=one(b'authorization')
                if self.clock()>=self.operator_deadline or len(auth)>256 or not auth.startswith('Bearer ') or not hmac.compare_digest(digest(auth[7:]),self.operator_digest):
                    status=401;result={'error':'unauthorized'}
                elif scope.get('query_string') or method!=('GET' if path=='/status' else 'POST'):
                    raise Reject('ADMIN_REQUEST')
                else:
                    while True:
                        msg=await receive()
                        if msg['type']!='http.request' or msg.get('body'): raise Reject('EMPTY_BODY_REQUIRED')
                        if not msg.get('more_body'): break
                    if path=='/initialize': result=self.db.initialize()
                    elif path=='/activate':
                        if not self.issuer: raise Reject('NO_SYNTHETIC_CONFIG')
                        result=self.db.activate(self.issuer)
                    else:
                        with self.db.tx() as run:
                            row=self.db.inspect(run)
                        result={'receipt':digest(self.db.receipt),'initialized':True,'activated':row[4], 'deadline':row[5]}
                    status=200
            elif self.oauth and path in ('/.well-known/oauth-authorization-server','/jwks','/authorize','/consent','/token','/ready'):
                with self.db.tx() as run:
                    row=self.db.inspect(run)
                    if row[0]!=self.issuer.pin or not row[4] or row[5]!=self.issuer.cfg.deadline: raise Reject('NOT_ACTIVE')
                forwarded=dict(scope,scheme='https')
                await self.oauth(forwarded,receive,send); return
            else: status=404;result={'error':'not_found'}
        except Reject: status=409;result={'error':'state_or_request_rejected'}
        except Exception: status=503;result={'error':'temporarily_unavailable'}
        await JSONResponse(result,status_code=status,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'})(scope,receive,send)

def create_app():
    db=Database(os.environ['DATABASE_URL'],json.loads(os.environ['DATABASE_BINDING']))
    issuer=None
    if os.environ.get('SYNTHETIC_OAUTH_ENABLED','false')=='true':
        config=Config(**json.loads(os.environ['SYNTHETIC_OAUTH_CONFIG']))
        key=serialization.load_pem_private_key(os.environ['SYNTHETIC_SIGNING_KEY'].encode(),password=None)
        issuer=Issuer(config,db,key)
    elif os.environ.get('SYNTHETIC_OAUTH_ENABLED','false')!='false': raise Reject('MODE')
    return Application(db,os.environ['ISSUER_ORIGIN'],os.environ['OPERATOR_DIGEST'],int(os.environ['OPERATOR_DEADLINE']),issuer)
