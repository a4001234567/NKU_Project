import os
import re
import json
import pickle
import random
import getpass
import requests
from urllib.parse import unquote
from base64 import b64encode,b64decode
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.asymmetric.padding import OAEP,MGF1 

public_key = serialization.load_pem_public_key(b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+aYeuXzRlIb/a8SsVX/
I1X6nEceImBiFyU7REuc7szvxr9nPoCiL9i/NSHk9/ds2fn06P93wBTKO+2cjIOM
i8Qk+x08uq+uHNPYMHguFAm6qaopH03BvPyI2fItnbb5SmBfY1mBS4YWs1b+oBlz
uAWdh1/1Qnp/5o9cdZZ+Khd2N1G5XJZa1JnKM4hSGA2KgjdikawddXwqx+U07Zzy
ITlgV+aYatfI8Xzm7DKZ8BSKeTw9Bpy00KgewwcafYCBO7tLRHtggmenJ1SxObIV
2ikp5I+SLymtegmUTsZ6yOAjB/5SaLPI9QuXn0HYEgbtdE7nLvbOCD4Yv/ZVrDoe
3wIDAQAB
-----END PUBLIC KEY-----""")

key = os.urandom(32)

def public_key_encrypt(message):
    ciphertext = public_key.encrypt(
        message,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return ciphertext

def encrypt(message):
    iv = os.urandom(16)
    cipher = Cipher(AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = PKCS7(AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
    
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return b64encode(iv + ciphertext)

def decrypt(encrypted_message):
    data = b64decode(encrypted_message)
    iv = data[:16]  # Extract the IV
    ciphertext = data[16:]  # Extract the ciphertext
    decryptor = Cipher(AES(key), modes.CBC(iv)).decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(AES.block_size).unpadder()
    return unpadder.update(padded_message) + unpadder.finalize()

def login(username,password,url):
    data = b','.join((bytes(username,'ascii'),bytes(url.replace('.nankai.edu.cn','@@').replace('http','_@').replace('login','@_'),'ascii'),password.encode('ascii')))
    encoded_data = b64encode(public_key_encrypt(key))
    response = requests.post(f'http://82.157.171.33/cgi-bin/login?{encrypt(data).decode()}',data=encoded_data,timeout=5)
    decrypted_message = decrypt(response.content)
    response_obj = pickle.loads(decrypted_message)
    return response_obj

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

def new_session():
    user_agent = random.choice(user_agents)
    session = requests.Session()
    session.headers['User-Agent'] = user_agent
    return session

eamurl = 'https://eamis.nankai.edu.cn'
refer_finder = re.compile(r'''self.location='([a-zA-Z./]+)';''')
def eam_login(username,password,session=None):
    if not session:
        session = new_session()
    
    response = session.get(eamurl,verify=False)
    assert '/eams/home.action' == refer_finder.search(response.text).group(1)

    response = session.get(eamurl+'/eams/home.action',verify=False,allow_redirects=False)
    next_url = eamurl+response.headers['Location']

    response = session.get(next_url,verify=False,allow_redirects=False)

    login_url = login(username,password,response.headers['Location'])
    
    response = session.get(login_url)
    return session,response
libic_url = "https://libic.nankai.edu.cn"
def libic_login(username,password,libic_session=None):
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

    login_url = login(username,password,refered)

    response = libic_session.get(login_url,timeout=0.5,data={'Upgrade-Insecure-Requests':1})
  
    response = libic_session.get("https://libic.nankai.edu.cn/ic-web/auth/userInfo")
    assert "查询成功" in response.text
    return libic_session,None
if __name__ == "__main__":
  username = input("USERNAME:")
  password = ''
  if os.path.exists("passwords.list"):
      with open("passwords.list",'r') as file:
          for line in file:
              if line.startswith(username):
                  password = line.split('\t')[-1].rstrip()
                  print("getting password from cache...")
  if not password:
      password = getpass.getpass("PASSWORD:")
      with open("passwords.list","a") as file:
          file.write(f"\n{username}\t{password}")
  url='https://sso.nankai.edu.cn/sso/login?service=https://dzpz.nankai.edu.cn'
  res = login(username,password,url)
