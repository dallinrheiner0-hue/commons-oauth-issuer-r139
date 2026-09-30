"""Bounded, single-owner OAuth trial issuer. No Commons messages or runner code."""
import base64
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

import jwt

class Reject(Exception): pass

def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))
def challenge(value): return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip('=')

@dataclass(frozen=True)
class Config:
    issuer: str
    resource: str
    client_id: str
    callback: str
    subject: str
    grant: str
    kid: str
    login_digest: str
    deadline: int
    scopes: str = 'commons:send'

class Issuer:
    def __init__(self,config,db,private_key,clock=time.time,fault=lambda _:None):
        self.cfg,self.db,self.key,self.clock,self.fault=config,db,private_key,clock,fault
        if config.subject!='synthetic-owner' or config.grant!='synthetic-grant-r139':
            raise Reject('SYNTHETIC_ONLY')
        for url in (config.issuer,config.resource,config.callback):
            p=urlsplit(url)
            if p.scheme!='https' or not p.hostname or p.username or p.password or p.query or p.fragment:
                raise Reject('HTTPS_CONFIG_REQUIRED')
        if config.callback!='https://chatgpt.com/connector_platform_oauth_redirect':
            raise Reject('REVIEW_CALLBACK_REQUIRED')
        if config.scopes!='commons:send' or not re.fullmatch('[a-f0-9]{64}',config.login_digest):
            raise Reject('TRIAL_CONFIG')
        if type(config.deadline) is not int or not 0<config.deadline<=clock()+86400:
            raise Reject('BOUNDED_TRIAL_DEADLINE_REQUIRED')
        public=private_key.public_key()
        if getattr(public,'key_size',0)<2048:
            raise Reject('SIGNING_KEY_TOO_SMALL')
        self.jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public))
        self.jwk.update(kid=config.kid,alg='RS256',use='sig')
        self.pin=digest(canonical({'config':asdict(config),'public_key':self.jwk}))

    def admit(self,run):
        row=run('SELECT pin,issued,attempts FROM trial WHERE id=1').fetchone()
        if not row or row[0]!=self.pin or self.clock()>=self.cfg.deadline:
            raise Reject('TRIAL_UNAVAILABLE')
        return row

    def metadata(self):
        c=self.cfg
        return dict(issuer=c.issuer,authorization_endpoint=c.issuer+'/authorize',token_endpoint=c.issuer+'/token',
            jwks_uri=c.issuer+'/jwks',response_types_supported=['code'],grant_types_supported=['authorization_code'],
            token_endpoint_auth_methods_supported=['none'],code_challenge_methods_supported=['S256'],
            scopes_supported=[c.scopes],authorization_response_iss_parameter_supported=True)

    def start(self,params):
        c=self.cfg
        expected={'client_id':c.client_id,'redirect_uri':c.callback,'resource':c.resource,
                  'response_type':'code','code_challenge_method':'S256','scope':c.scopes}
        if set(params)!=set(expected)|{'state','code_challenge'} or any(params[k]!=v for k,v in expected.items()):
            raise Reject('AUTHORIZATION_REQUEST')
        if not re.fullmatch('[A-Za-z0-9_-]{43}',params['code_challenge']) or not 1<=len(params['state'])<=512:
            raise Reject('PKCE_OR_STATE')
        flow,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
        with self.db.tx() as run:
            row=self.admit(run)
            if row[1] or row[2]>=32: raise Reject('TRIAL_CONSUMED_OR_LIMITED')
            changed=run('UPDATE trial SET attempts=attempts+1 WHERE id=1 AND attempts<32 AND issued=0')
            if changed.rowcount!=1: raise Reject('TRIAL_CONSUMED_OR_LIMITED')
            run('INSERT INTO flows VALUES(?,?,?,0)',
                (digest(flow),canonical({'params':params,'csrf':digest(csrf)}),min(int(self.clock())+300,c.deadline)))
        return flow,csrf

    def consent(self,flow,csrf,secret,origin):
        code=secrets.token_urlsafe(32); target=None
        with self.db.tx() as run:
            self.admit(run)
            row=run('SELECT payload,expires FROM flows WHERE id=? AND used=0',(digest(flow),)).fetchone()
            if not row or row[1]<=self.clock(): raise Reject('FLOW_UNAVAILABLE')
            payload=json.loads(row[0])
            if origin!=self.cfg.issuer or not hmac.compare_digest(digest(csrf),payload['csrf']):
                raise Reject('CSRF')
            if run('UPDATE flows SET used=1 WHERE id=? AND used=0',(digest(flow),)).rowcount!=1:
                raise Reject('FLOW_CONSUMED')
            # A wrong secret consumes this flow, without exposing which check failed.
            if hmac.compare_digest(digest(secret),self.cfg.login_digest):
                run('INSERT INTO codes VALUES(?,?,?,0)',(digest(code),canonical(payload['params']),
                    min(int(self.clock())+120,self.cfg.deadline)))
                target=self.cfg.callback+'?'+urlencode({'code':code,'state':payload['params']['state'],'iss':self.cfg.issuer})
        if target is None: raise Reject('LOGIN_FAILED')
        return target

    def exchange(self,params):
        c=self.cfg
        expected={'grant_type':'authorization_code','client_id':c.client_id,'redirect_uri':c.callback,'resource':c.resource}
        if set(params)!=set(expected)|{'code','code_verifier'} or any(params[k]!=v for k,v in expected.items()):
            raise Reject('TOKEN_REQUEST')
        verifier=params['code_verifier']
        if not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}',verifier): raise Reject('PKCE')
        token=None
        with self.db.tx() as run:
            row=self.admit(run)
            if row[1]: raise Reject('TRIAL_CONSUMED')
            saved=run('SELECT payload,expires FROM codes WHERE id=? AND used=0',(digest(params['code']),)).fetchone()
            if not saved or saved[1]<=self.clock(): raise Reject('CODE_UNAVAILABLE')
            data=json.loads(saved[0])
            if not hmac.compare_digest(challenge(verifier),data['code_challenge']): raise Reject('PKCE')
            if run('UPDATE codes SET used=1 WHERE id=? AND used=0',(digest(params['code']),)).rowcount!=1:
                raise Reject('CODE_CONSUMED')
            if run('UPDATE trial SET issued=1 WHERE id=1 AND issued=0').rowcount!=1:
                raise Reject('TRIAL_CONSUMED')
            now=int(self.clock()); expires=min(now+600,c.deadline)
            token=jwt.encode(dict(iss=c.issuer,aud=c.resource,sub=c.subject,client_id=c.client_id,
                commons_grant=c.grant,scope=c.scopes,iat=now,nbf=now,exp=expires,jti=secrets.token_urlsafe(24)),
                self.key,algorithm='RS256',headers={'kid':c.kid})
            self.fault('before_token_commit')
        self.fault('after_token_commit')
        return {'access_token':token,'token_type':'Bearer','expires_in':expires-now,'scope':c.scopes}
