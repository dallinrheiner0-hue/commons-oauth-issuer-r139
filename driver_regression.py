"""Real Psycopg parser regression; never opens a connection."""
from psycopg.adapt import Transformer
from psycopg._queries import PostgresQuery

def check():
    q=PostgresQuery(Transformer())
    text="SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg_%'"
    q.convert(text, None)
    assert q.query.decode()==text
    q.convert('SELECT %s', ('synthetic',))
    assert q.query==b'SELECT $1'
    print('Parameterless SQL and bound-parameter regression PASS; no connection')

if __name__=='__main__': check()
