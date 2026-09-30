import os
import uvicorn
if __name__=='__main__':
    uvicorn.run('app:create_app',factory=True,host='0.0.0.0',port=int(os.environ.get('PORT','10000')),workers=1,proxy_headers=False,access_log=False,lifespan='off',log_level='warning')
