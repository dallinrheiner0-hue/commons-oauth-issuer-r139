"""Small OAuth HTTP surface; does not host MCP or execute messages."""
import html
from urllib.parse import parse_qsl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route
from starlette.middleware.base import BaseHTTPMiddleware
from oauth import Reject

def fields(raw):
    if len(raw)>16384: raise Reject('BODY_LIMIT')
    pairs=parse_qsl(raw.decode('utf-8'),keep_blank_values=True,strict_parsing=True,max_num_fields=16)
    if len(dict(pairs))!=len(pairs): raise Reject('DUPLICATE_FIELDS')
    return dict(pairs)

def app_for(issuer):
    async def metadata(request): return JSONResponse(issuer.metadata())
    async def jwks(request): return JSONResponse({'keys':[issuer.jwk]})
    async def authorize(request):
        flow,csrf=issuer.start(fields(request.scope['query_string']))
        # Server-owned copy. No model text, claims or redirects are rendered.
        page='''<!doctype html><html lang="en"><meta name="viewport" content="width=device-width">
<title>Commons trial sign-in</title><h1>Commons private conversation trial</h1>
<p>Authorize ChatGPT to read and send messages only in the Dallin / Proteus direct Commons conversation.
This grants no execution authority or access to other conversations. Use this connection only in the selected private Proteus chat. The trial ends within 24 hours.</p>
<form method="post" action="/consent"><input type="hidden" name="csrf" value="%s">
<label>Trial passphrase <input name="secret" type="password" autocomplete="off" required maxlength="256"></label>
<button type="submit">Allow this trial</button></form></html>''' % html.escape(csrf,quote=True)
        response=HTMLResponse(page)
        response.set_cookie('__Host-commons-flow',flow,secure=True,httponly=True,samesite='lax',max_age=300,path='/')
        return response
    async def body(request):
        if request.headers.get('content-type','').split(';')[0]!='application/x-www-form-urlencoded':
            raise Reject('CONTENT_TYPE')
        raw=bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw)>16384: raise Reject('BODY_LIMIT')
        return fields(bytes(raw))
    async def consent(request):
        form=await body(request)
        if set(form)!={'csrf','secret'} or not 32<=len(form['secret'])<=256: raise Reject('FORM')
        flow=request.cookies.get('__Host-commons-flow','')
        if len(flow)>128: raise Reject('FLOW')
        target=issuer.consent(flow,form['csrf'],form['secret'],request.headers.get('origin',''))
        response=RedirectResponse(target,status_code=303)
        response.delete_cookie('__Host-commons-flow',secure=True,httponly=True,samesite='lax',path='/')
        return response
    async def token(request): return JSONResponse(issuer.exchange(await body(request)))
    async def ready(request):
        with issuer.db.tx() as run: issuer.admit(run)
        return JSONResponse({'ready':True})
    app=Starlette(routes=[Route('/.well-known/oauth-authorization-server',metadata),Route('/jwks',jwks),
        Route('/authorize',authorize),Route('/consent',consent,methods=['POST']),
        Route('/token',token,methods=['POST']),Route('/ready',ready)])

    async def boundary(request,call_next):
        try:
            if str(request.base_url).rstrip('/')!=issuer.cfg.issuer: raise Reject('ORIGIN')
            response=await call_next(request)
        except (Reject,ValueError,UnicodeError):
            response=JSONResponse({'error':'invalid_request'},status_code=400)
        except Exception:
            # Never return DSNs, secrets or database diagnostics to the caller.
            response=JSONResponse({'error':'temporarily_unavailable'},status_code=503)
        response.headers.update({'Cache-Control':'no-store','Pragma':'no-cache','Referrer-Policy':'no-referrer',
            'X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})
        return response
    app.add_middleware(BaseHTTPMiddleware,dispatch=boundary)
    return app
