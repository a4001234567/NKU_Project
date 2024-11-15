import re
import os
import rsa
import sys
import time
import json
import random
import base64
import getpass
import hashlib
import logging
import requests
import datetime
from urllib.parse import quote,unquote
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

user_agents = ('Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15',
               'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
               'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;'
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SE 2.X MetaSr 1.0; SE 2.X MetaSr 1.0; .NET CLR 2.0.50727; SE 2.X MetaSr 1.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)',
               'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1',
               'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0) Gecko/20100101 Firefox/6.0',
               'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
               'Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.9.168 Version/11.50',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; Tablet PC 2.0; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; InfoPath.3)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB7.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ) AppleWebKit/534.12 (KHTML, like Gecko) Maxthon/3.0 Safari/534.12',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E; SE 2.X MetaSr 1.0)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.3 (KHTML, like Gecko) Chrome/6.0.472.33 Safari/534.3 SE 2.X MetaSr 1.0',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.41 Safari/535.1 QQBrowser/6.9.11079.201',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E) QQBrowser/6.9.11079.201',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)')

logger = logging.getLogger('Login')
logger.setLevel(logging.DEBUG)
fmter = logging.Formatter(fmt="%(asctime)s:%(levelname)s:\n%(message)s")
fhandler = logging.FileHandler("login.log")
fhandler.setFormatter(fmter)
fhandler.setLevel(logging.DEBUG)
logger.addHandler(fhandler)
shandler = logging.StreamHandler(sys.stdout)
shandler.setLevel(logging.DEBUG)
logger.addHandler(shandler)

def new_session():
    user_agent = random.choice(user_agents)
    session = requests.Session()
    session.headers['User-Agent'] = user_agent
    return session
ssourl = 'https://sso.nankai.edu.cn'
iamurl = 'https://iam.nankai.edu.cn'

class account:
    def __init__(self,aid,apassword):
        self.ID = aid
        self.PASSWORD = apassword

lt_finder = re.compile(r"var _lt = \"(\d+)\";")

key_string = b'''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfy7Co/zbDUegHFoAxuEzAyllnf6dxt50iipCVVns8Vzx6BCJmYEYa6/OlLrhJSB7yW4igfyotKkwsd8lA1d3nP6HWb7s4t2HWTKo/Tcb/LVzUGX9Juz8ifF1tHduAAubJNVlArr21uu1atk9y4K6Um3MKwWw5tQ/bMP4NdYMaRQIDAQAB
-----END PUBLIC KEY-----
'''
publicKey = rsa.PublicKey.load_pkcs1_openssl_pem(key_string)

key = bytes("8bfa9ad090fbbf87e518f1ce24a93eee",encoding='utf8')
iv = bytes("fbfae671950f423b58d49b91ff6a22b97428219c",encoding='utf8')[:16]

def rsaencrypt(content):
    return base64.b64encode(rsa.encrypt(content,publicKey))

def getIAMenc(message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    message = message.encode('ascii')
    
    # Pad the message to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
        
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return ciphertext.hex()

def hexmd5(content):
    return hashlib.md5(content).hexdigest()

def login(login_session,url,account):
    if url.startswith(iamurl):
        headers = {}
        if 'csrf-token' in login_session.cookies:
            headers['csrf-token'] = login_session.cookies['csrf-token']
        response = login_session.get(url,verify=False,allow_redirects=True,headers = headers)
        
        data = dict(login_scene='feilian',account_type='userid')
        data['password'] = getIAMenc(account.PASSWORD)
        data['account'] = account.ID
        headers = {}
        headers['Host'] = "iam.nankai.edu.cn"
        headers['X-Version-Check'] = "0"
        headers['Sec-Fetch-Site'] =  "same-origin"
        headers['Origin'] = iamurl
        headers['Content-Type'] = "application/json"
        headers['Sec-Fetch-Dest'] = "empty"
        headers['X-Fe-Version'] = "3.0.3.4344"
        headers['csrf-token'] = login_session.cookies['csrf-token']
    
        response = login_session.post(iamurl+"/api/v1/login?os=web",json=data,headers=headers,allow_redirects=False)
        return iamurl+json.loads(response.text)['data']['next']['link']
    elif url.startswith(ssourl):
        year = time.gmtime().tm_year
        cur_time = int(time.time()*1000)
        def base():
            return base64.b64encode(f'{year*cur_time*33}{int(1000*random.random())}'.encode('ascii'))
        response = login_session.get(url)
        service_name = unquote(url[5+url[5:].find("http"):])
        lt = lt_finder.search(response.text).group(1)
        assert 'MYSELF_SESSION' in login_session.cookies

        response = login_session.post(ssourl+'/sso/loadcode',data='',headers=dict(Authorization=base(),Referer=url,Origin="https://sso.nankai.edu.cn"))
        rand = json.loads(response.text)['rand']
        t = rsaencrypt(bytes(my_account.PASSWORD,"utf-8"))
        data = dict(ajax = 1,
                    username = account.ID,
                    password = hexmd5(bytes(account.PASSWORD,"utf-8")),
                    lt = lt,
                    rand = rand,
                    t = t,
                    roleType = '',
                    service = service_name,
                    loginType=0)
        response = login_session.post(ssourl+"/sso/login",data=data)
        response_dict = json.loads(response.text)
        status = response_dict['status']
        assert status, f"Failed with {response.text}"
        message = response_dict['message']

        return f'{service_name}?ticket={message}'

eamurl = 'https://eamis.nankai.edu.cn'
refer_finder = re.compile(r'''self.location='([a-zA-Z./]+)';''')
def eam_login(user_account,session=None):
    if not session:
        session = new_session()
    
    response = session.get(eamurl,verify=False)
    assert '/eams/home.action' == refer_finder.search(response.text).group(1)

    response = session.get(eamurl+'/eams/home.action',verify=False,allow_redirects=False)
    next_url = eamurl+response.headers['Location']

    response = session.get(next_url,verify=False,allow_redirects=False)

    login_url = login(session,response.headers['Location'],user_account)
    
    response = session.get(login_url)
    return session,response

libic_url = "https://libic.nankai.edu.cn"
def libic_login(user_account,libic_session=None):
    if not libic_session:
        libic_session = new_session()

    libic_session.get(libic_url)

    libic_session.get('https://libic.nankai.edu.cn/ic-web/auth/userInfo')
    
    headers = {}
    headers['lan'] = '1'
    headers['Referer'] = libic_url
    
    response = libic_session.get(libic_url+"/ic-web/auth/address?finalAddress="+libic_url+"&errPageUrl="+libic_url+"/#/error&manager=false&consoleType=16",verify=False,headers=headers)
    refered = json.loads(response.text)['data']
    assert refered.startswith(libic_url+'/authcenter/toLoginPage'),refered

    del headers['lan']
    response = libic_session.get(refered,verify=False,allow_redirects=False,headers=headers)
    refered = response.headers['Location']
    assert refered.startswith(ssourl) or refered.startswith(iamurl),refered

    login_url = login(libic_session,refered,user_account)

    response = libic_session.get(login_url,timeout=0.5,data={'Upgrade-Insecure-Requests':1})
  
    response = libic_session.get("https://libic.nankai.edu.cn/ic-web/auth/userInfo")
    assert "查询成功" in response.text
    return libic_session
if __name__ == "__main__":
  user_name = input("USERNAME:")
  password = ''
  if os.path.exists("passwords.list"):
      with open("passwords.list",'r') as file:
          for line in file:
              if line.startswith(user_name):
                  password = line.split('\t')[-1].rstrip()
                  print("getting password from cache...")
  if not password:
      password = getpass.getpass("PASSWORD:")
      with open("passwords.list","a") as file:
          file.write(f"\n{user_name}\t{password}")
  
  my_account = account(user_name,password)
  
  sess = new_session()
  s = login(sess,'https://sso.nankai.edu.cn/sso/login?service=https://dzpz.nankai.edu.cn',my_account)
  print(s)
