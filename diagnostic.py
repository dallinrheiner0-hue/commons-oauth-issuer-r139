"""Fixed, bounded observation. No caller-controlled query, identifier or state write."""
import hashlib
import json
import re
import time
from urllib.parse import urlsplit, unquote

BINDING = {'resource_id':'dpg-daum9cgu01pc7389adgg-a',
 'database':'commons_oauth_state_r139','user':'commonsoauthstater139_xxmz_user',
 'workspace':'tea-daulra8473hc73bo7ls0','initialization_id':'1b0ef32352c17ab952969d637ae5844f'}
RECEIPT_HASH = '11389382b6232c950df6292ebcf776acda2faee15e771c1b322a5e82bea19fec'
RECEIPT = json.dumps({'schema':'9a501ce5b0b4ff6ec1f6ecb22d5ee8a28ddf7d5201f5590ece4655524593b309',
 'binding':BINDING,'event':'initialized-no-grant'},sort_keys=True,separators=(',',':'))
assert hashlib.sha256(RECEIPT.encode()).hexdigest() == RECEIPT_HASH
UNINITIALIZED='UNINITIALIZED_AT_SNAPSHOT'
INITIALIZED='INITIALIZED_AT_SNAPSHOT'
FOREIGN='INCONSISTENT_OR_FOREIGN_AT_SNAPSHOT'
UNKNOWN='UNKNOWN'

# Raw PostgreSQL 18 expression metadata, never executed. Only source-location
# numbers/whitespace may differ. Unknown encodings fail closed. Linux x86_64.
CHECK = '''{OPEXPR :opno 96 :opfuncid 65 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 :args ({VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varnullingrels (b) :varlevelsup 0 :varreturningtype 0 :varnosyn 1 :varattnosyn 1 :location -1} {CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 1 0 0 0 0 0 0 0 ]}) :location -1}'''
def normalize_check(value):
    if not isinstance(value,str) or len(value)>2048: return None
    return ' '.join(re.sub(r':location -?\d+',':location -1',value).split())

# No pg_get_*(), user functions, expression evaluation, advisory locks or body reads.
# All identifiers are literal. LIMIT 65 + fetch cap rejects excessive catalog state.
QUERIES = {
 'identity':'SELECT current_catalog, current_user',
 'version':'SHOW server_version_num',
 'default_ro':'SHOW default_transaction_read_only',
 'ro':'SHOW transaction_read_only',
 'isolation':'SHOW transaction_isolation',
 'schemas':"SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%' LIMIT 65",
 'procedures':"SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' LIMIT 1",
 'extensions':"SELECT extname FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql' LIMIT 65",
 'relations':"SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relispartition,c.relhassubclass,c.relam FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname LIMIT 65",
 'types':"SELECT t.typname,t.typtype,t.typrelid <> 0,t.typelem <> 0 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' ORDER BY t.typname LIMIT 65",
 'extra':"SELECT 1 FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid=o.oprnamespace WHERE n.nspname='public' UNION ALL SELECT 1 FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE n.nspname='public' UNION ALL SELECT 1 FROM pg_catalog.pg_conversion c JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public' UNION ALL SELECT 1 FROM pg_catalog.pg_event_trigger UNION ALL SELECT 1 FROM pg_catalog.pg_foreign_server LIMIT 1",
 'columns':"SELECT c.relname,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.atthasdef,a.attidentity,a.attgenerated,a.attisdropped,a.attndims FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 ORDER BY c.relname,a.attnum LIMIT 65",
 'constraints':"SELECT t.relname,c.contype,c.conkey,c.condeferrable,c.condeferred,c.convalidated,c.conenforced,c.conislocal,c.coninhcount,c.connoinherit,c.conbin::text FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace LEFT JOIN pg_catalog.pg_class t ON t.oid=c.conrelid WHERE n.nspname='public' ORDER BY t.relname,c.contype,c.conkey LIMIT 65",
 'indexes':"SELECT t.relname,i.indnatts,i.indnkeyatts,i.indisunique,i.indnullsnotdistinct,i.indisprimary,i.indisexclusion,i.indimmediate,i.indisvalid,i.indisready,i.indislive,i.indkey::text,i.indexprs IS NULL,i.indpred IS NULL FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' ORDER BY t.relname LIMIT 65",
 'hooks':"SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' UNION ALL SELECT 1 FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' UNION ALL SELECT 1 FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' LIMIT 1",
 # Boolean comparisons only; no pin, receipt, flow or code value is returned.
 'trial':"SELECT id=1,pin='',issued=0,attempts=0,receipt=%s,activated=0,deadline=0 FROM ONLY public.trial LIMIT 2",
 'flows':'SELECT 1 FROM ONLY public.flows LIMIT 1',
 'codes':'SELECT 1 FROM ONLY public.codes LIMIT 1',
}

def valid_binding(dsn,binding):
    try:
        p=urlsplit(dsn)
        return (binding==BINDING and p.scheme in ('postgres','postgresql') and
          p.hostname==BINDING['resource_id'] and p.port in (None,5432) and
          not p.query and not p.fragment and bool(p.password) and
          unquote(p.path[1:])==BINDING['database'] and unquote(p.username or '')==BINDING['user'])
    except (ValueError,TypeError): return False

def expected_columns():
    result=[]
    for table,fields in (
      ('codes',[('id',25),('payload',25),('expires',20),('used',23)]),
      ('flows',[('id',25),('payload',25),('expires',20),('used',23)]),
      ('trial',[('id',23),('pin',25),('issued',23),('attempts',23),('receipt',25),('activated',20),('deadline',20)])):
        result.extend((table,i,name,typ,-1,True,False,'','',False,0) for i,(name,typ) in enumerate(fields,1))
    return result

def shape(run):
    if any(run(k) for k in ('schemas','procedures','extensions','extra')): return FOREIGN
    rels=sorted(run('relations')); types=sorted(run('types'))
    if not rels:
        if types or run('constraints') or run('hooks'): return FOREIGN
        return UNINITIALIZED
    expected=sorted([(t,'r','p',False,False,False,False,2) for t in ('trial','flows','codes')]+
        [(t+'_pkey','i','p',False,False,False,False,403) for t in ('trial','flows','codes')])
    if rels!=expected: return FOREIGN
    if types!=sorted([(t,'c',True,False) for t in ('trial','flows','codes')]+[('_'+t,'b',False,True) for t in ('trial','flows','codes')]): return FOREIGN
    if run('columns')!=expected_columns() or run('hooks'): return FOREIGN
    constraints=run('constraints'); seen=[]
    for table,kind,keys,defer,deferred,validated,enforced,local,inh,noinh,expr in constraints:
        if defer or deferred or not validated or not enforced or not local or inh: return FOREIGN
        if kind=='c':
            if table!='trial' or keys!=[1] or noinh or normalize_check(expr)!=normalize_check(CHECK): return FOREIGN
        elif kind=='p':
            if keys!=[1] or expr is not None or not noinh: return FOREIGN
        elif kind=='n':
            if expr is not None or noinh or keys is None or len(keys)!=1: return FOREIGN
        else: return FOREIGN
        seen.append((table,kind,tuple(keys)))
    required=[(t,'p',(1,)) for t in ('codes','flows','trial')]+[('trial','c',(1,))]
    required += [(t,'n',(i,)) for t,i,*_ in expected_columns()]
    if sorted(seen)!=sorted(required): return FOREIGN
    expected_indexes=[(t,1,1,True,False,True,False,True,True,True,True,'1',True,True) for t in ('codes','flows','trial')]
    if run('indexes')!=expected_indexes: return FOREIGN
    if run('trial',(RECEIPT,))!=[(True,)*7] or run('flows') or run('codes'): return FOREIGN
    return INITIALIZED

OPTIONS='-c default_transaction_read_only=on -c search_path=pg_catalog -c statement_timeout=2000 -c lock_timeout=1000 -c transaction_timeout=12000 -c idle_in_transaction_session_timeout=3000'

def observe(dsn,binding,connect,clock=time.monotonic):
    """Any uncertainty, including rollback/close, suppresses provisional classification."""
    if not valid_binding(dsn,binding): return UNKNOWN,'BINDING_REJECTED'
    c=None; result=UNKNOWN; reason='OBSERVATION_UNCERTAIN'; started=clock()
    try:
        c=connect(dsn,connect_timeout=4,sslmode='require',options=OPTIONS,autocommit=True)
        c.execute('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        def run(key,args=()):
            if clock()-started>18: raise TimeoutError()
            rows=c.execute(QUERIES[key],args).fetchmany(65)
            if len(rows)>=65: raise ValueError('bounded result exceeded')
            return [tuple(r) for r in rows]
        if (run('identity')!=[(BINDING['database'],BINDING['user'])] or
            run('default_ro')!=[('on',)] or run('ro')!=[('on',)] or
            run('isolation')!=[('repeatable read',)]): raise ValueError('session guard')
        v=run('version')
        if len(v)!=1 or not 180000<=int(v[0][0])<190000: raise ValueError('version guard')
        result=shape(run); reason='SNAPSHOT_OBSERVED'
    except Exception:
        result=UNKNOWN; reason='OBSERVATION_UNCERTAIN'
    finally:
        if c is not None:
            try: c.execute('ROLLBACK')
            except Exception: result=UNKNOWN; reason='CLEANUP_UNCERTAIN'
            try: c.close()
            except Exception: result=UNKNOWN; reason='CLEANUP_UNCERTAIN'
    if clock()-started>20: return UNKNOWN,'TIME_BOUND_EXCEEDED'
    return result,reason
