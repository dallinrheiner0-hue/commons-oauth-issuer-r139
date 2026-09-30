"""PostgreSQL-only storage. Schema changes occur only on explicit initialize()."""
from contextlib import contextmanager
import json
import re
import time
from urllib.parse import urlsplit, unquote
import psycopg
from oauth import Reject, canonical, digest

DDL = (
    'CREATE TABLE public.trial (id INTEGER PRIMARY KEY CHECK(id=1), pin TEXT NOT NULL, issued INTEGER NOT NULL, attempts INTEGER NOT NULL, receipt TEXT NOT NULL, activated BIGINT NOT NULL, deadline BIGINT NOT NULL)',
    'CREATE TABLE public.flows (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expires BIGINT NOT NULL, used INTEGER NOT NULL)',
    'CREATE TABLE public.codes (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expires BIGINT NOT NULL, used INTEGER NOT NULL)',
)
SCHEMA = digest(canonical(DDL))
SHAPE = [('trial','id','integer'),('trial','pin','text'),('trial','issued','integer'),('trial','attempts','integer'),('trial','receipt','text'),('trial','activated','bigint'),('trial','deadline','bigint'),('flows','id','text'),('flows','payload','text'),('flows','expires','bigint'),('flows','used','integer'),('codes','id','text'),('codes','payload','text'),('codes','expires','bigint'),('codes','used','integer')]

class Database:
    def __init__(self, dsn, binding):
        p=urlsplit(dsn)
        if (p.scheme not in ('postgres','postgresql') or p.hostname!=binding['resource_id']
            or p.port not in (None,5432) or p.query or p.fragment
            or unquote(p.path[1:])!=binding['database'] or unquote(p.username or '')!=binding['user']
            or not p.password or binding['database']!='commons_oauth_state_mvp'
            or binding['workspace']!='tea-dauni48473hc73bts5kg'
            or not re.fullmatch(r'dpg-[a-z0-9]+-a',binding['resource_id'])
            or not re.fullmatch(r'[a-f0-9]{32}',binding['initialization_id'])):
            raise Reject('DATABASE_BINDING')
        self.dsn,self.binding=dsn,binding
        self.receipt=canonical({'schema':SCHEMA,'binding':binding,'event':'initialized-no-grant'})

    @contextmanager
    def tx(self):
        c=psycopg.connect(self.dsn,connect_timeout=5,sslmode='require',options='-c search_path=public -c statement_timeout=5000 -c lock_timeout=3000')
        try:
            identity=c.execute('SELECT current_database(), current_user').fetchone()
            if tuple(identity)!=(self.binding['database'],self.binding['user']): raise Reject('DATABASE_IDENTITY')
            def run(sql,values=()): return c.execute(sql.replace('?', '%s'), values if values else None)
            yield run
            c.commit()
        except BaseException:
            c.rollback(); raise
        finally: c.close()

    def shape(self,run):
        # Reject unrelated public objects, views, functions and foreign user schemas.
        if run("SELECT nspname FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%'").fetchall(): raise Reject('FOREIGN_SCHEMA')
        if run("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'").fetchone(): raise Reject('FOREIGN_FUNCTION')
        objects=run("SELECT relname,relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND relkind <> 'i'").fetchall()
        if not objects: return False
        if sorted(objects)!=[('codes','r'),('flows','r'),('trial','r')]: raise Reject('PARTIAL_OR_FOREIGN_STATE')
        columns=run("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position").fetchall()
        if sorted(columns)!=sorted(SHAPE): raise Reject('SCHEMA_SHAPE')
        constraints=run("SELECT t.relname,pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND c.contype <> 'n'").fetchall()
        expected=[('codes','PRIMARY KEY (id)'),('flows','PRIMARY KEY (id)'),('trial','PRIMARY KEY (id)'),('trial','CHECK ((id = 1))')]
        # PostgreSQL 18 can expose NOT NULL as constraints as well as attnotnull.
        if sorted(constraints)!=sorted(expected): raise Reject('CONSTRAINTS')
        if run("SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND (is_nullable <> 'NO' OR column_default IS NOT NULL)").fetchone(): raise Reject('COLUMN_CONSTRAINTS')
        if run("SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal").fetchone(): raise Reject('TRIGGERS')
        if run("SELECT 1 FROM pg_policies WHERE schemaname='public'").fetchone(): raise Reject('POLICIES')
        return True

    def inspect(self,run):
        if not self.shape(run): raise Reject('UNINITIALIZED')
        rows=run('SELECT pin,issued,attempts,receipt,activated,deadline FROM trial WHERE id=1').fetchall()
        if len(rows)!=1 or rows[0][3]!=self.receipt or run('SELECT COUNT(*) FROM trial').fetchone()[0]!=1: raise Reject('RECEIPT_MISMATCH')
        return rows[0]

    def initialize(self,fault=lambda _:None):
        with self.tx() as run:
            run('SELECT pg_advisory_xact_lock(139139)')
            if self.shape(run):
                row=self.inspect(run)
                if tuple(row[:3])!=('',0,0) or tuple(row[4:])!=(0,0) or any(run('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('flows','codes')): raise Reject('NOT_PRISTINE_INITIALIZED')
                return {'result':'already_initialized','receipt':digest(self.receipt)}
            for sql in DDL:
                run(sql); fault('after_ddl')
            run('INSERT INTO trial VALUES(1,?,0,0,?,0,0)',('',self.receipt))
            fault('before_commit')
        fault('after_commit')
        return {'result':'initialized','receipt':digest(self.receipt)}

    def activate(self,issuer):
        now=int(issuer.clock())
        if not now<issuer.cfg.deadline<=now+86400: raise Reject('ACTIVATION_WINDOW')
        with self.tx() as run:
            run('SELECT pg_advisory_xact_lock(139139)')
            row=self.inspect(run)
            if row[0] or row[4] or row[5]: raise Reject('ALREADY_ACTIVATED')
            if row[1] or row[2] or any(run('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('flows','codes')): raise Reject('NOT_EMPTY')
            run('UPDATE trial SET pin=?,activated=?,deadline=? WHERE id=1',(issuer.pin,now,issuer.cfg.deadline))
        return {'result':'activated','deadline':issuer.cfg.deadline}
