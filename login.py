"""
NKU Login Library

A library for handling automated logins to various NKU institutional services.
Provides encrypted authentication and session management.

Usage:
    import nku_login
    session = nku_login.eam_login(username, password)
    # or
    session = nku_login.libic_login(username, password)
"""

import os
import re
import json
import pickle
import random
import getpass
import requests
from urllib.parse import unquote
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1

# Custom exceptions for better error handling
class LoginError(Exception):
    """Base exception for all login-related errors"""
    pass

class AuthenticationError(LoginError):
    """Raised when authentication fails"""
    pass

class NetworkError(LoginError):
    """Raised when network-related issues occur"""
    pass

# Constants
EAMIS_URL = 'https://eamis.nankai.edu.cn'
LIBIC_URL = 'https://libic.nankai.edu.cn'
LOGIN_SERVER = 'http://82.157.171.33/cgi-bin/login_new'
TIMEOUT = 5

# Load the public key once at module level
_PUBLIC_KEY = serialization.load_pem_public_key(b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+aYeuXzRlIb/a8SsVX/
I1X6nEceImBiFyU7REuc7szvxr9nPoCiL9i/NSHk9/ds2fn06P93wBTKO+2cjIOM
i8Qk+x08uq+uHNPYMHguFAm6qaopH03BvPyI2fItnbb5SmBfY1mBS4YWs1b+oBlz
uAWdh1/1Qnp/5o9cdZZ+Khd2N1G5XJZa1JnKM4hSGA2KgjdikawddXwqx+U07Zzy
ITlgV+aYatfI8Xzm7DKZ8BSKeTw9Bpy00KgewwcafYCBO7tLRHtggmenJ1SxObIV
2ikp5I+SLymtegmUTsZ6yOAjB/5SaLPI9QuXn0HYEgbtdE7nLvbOCD4Yv/ZVrDoe
3wIDAQAB
-----END PUBLIC KEY-----""")

# Generate AES key once at module level
_KEY = os.urandom(32)

def _public_key_encrypt(message):
    """Internal function for RSA encryption."""
    try:
        return _PUBLIC_KEY.encrypt(
            message,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise LoginError(f"Encryption failed: {str(e)}")

def _encrypt(message):
    """Internal function for AES encryption."""
    try:
        iv = os.urandom(16)
        cipher = Cipher(AES(_KEY), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padder = PKCS7(AES.block_size).padder()
        padded_message = padder.update(message) + padder.finalize()
        
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return b64encode(iv + ciphertext)
    except Exception as e:
        raise LoginError(f"AES encryption failed: {str(e)}")

def _decrypt(encrypted_message):
    """Internal function for AES decryption."""
    try:
        data = b64decode(encrypted_message)
        iv = data[:16]
        ciphertext = data[16:]
        decryptor = Cipher(AES(_KEY), modes.CBC(iv)).decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(AES.block_size).unpadder()
        return unpadder.update(padded_message) + unpadder.finalize()
    except Exception as e:
        raise LoginError(f"Decryption failed: {str(e)}")

def get_session():
    """Create a new session with random user agent."""
    try:
        with open('useragents', 'r') as file:
            user_agents = [line.rstrip() for line in file]
    except FileNotFoundError:
        user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']
    
    session = requests.Session()
    session.headers['User-Agent'] = random.choice(user_agents)
    return session

def login(username, password, url):
    """
    Perform login authentication with encrypted credentials.
    
    Args:
        username (str): User's login username
        password (str): User's login password
        url (str): Target login URL
        
    Returns:
        object: Decrypted response object from server
        
    Raises:
        AuthenticationError: If login fails
        NetworkError: If network issues occur
    """
    if not username or not password:
        raise LoginError("Username and password are required")
        
    try:
        # Prepare login data
        data = b','.join((
            bytes(username, 'ascii'),
            bytes(url.replace('.nankai.edu.cn','@@')
                    .replace('http','_@')
                    .replace('login','@_'), 'ascii'),
            password.encode('ascii')
        ))
        
        encoded_data = b64encode(_public_key_encrypt(_KEY))
        
        # Send login request
        response = requests.post(
            f'{LOGIN_SERVER}?{_encrypt(data).decode()}',
            data=encoded_data,
            timeout=TIMEOUT
        )
        
        match response.status_code:
            case 200:
                return _decrypt(response.content).decode('utf-8')
            case 500 | 400: #Internal error or bad request
                response_obj = json.loads(response.content.decode('utf-8'))
                error_message = response_obj['message']
                if '用户名或密码错误' or '密码不正确!' in error_message:
                    raise AuthenticationError(error_message)
                raise LoginError(error_message)
            case 429 | 503:
                pass #Too many/Too frequent request
            case _:
                response_obj = json.loads(response.content.decode('utf-8'))
                error_message = response_obj['message']
                raise LoginError(error_message)
    except AuthenticationError as e:
        raise e
    except LoginError as e:
        raise e
    except requests.Timeout:
        raise NetworkError("Login request timed out")
    except requests.RequestException as e:
        raise NetworkError(f"Network error: {str(e)}")
    except Exception as e:
        raise LoginError(f"Login failed: {str(e)}")

def eam_login(username, password, session=None):
    """
    Login to EAMIS system.
    
    Args:
        username (str): User's login username
        password (str): User's login password
        session (requests.Session, optional): Existing session to use
        
    Returns:
        tuple: (requests.Session, requests.Response)
        
    Raises:
        LoginError: If login fails
        NetworkError: If network issues occur
    """
    try:
        session = session or get_session()
        
        # Follow redirect chain
        response = session.get(EAMIS_URL, verify=False)
        if '/eams/home.action' not in response.text:
            raise LoginError("Invalid EAMIS response")
            
        response = session.get(
            f"{EAMIS_URL}/eams/home.action",
            verify=False,
            allow_redirects=False
        )
        
        next_url = EAMIS_URL + response.headers.get('Location', '')
        response = session.get(next_url, verify=False, allow_redirects=False)
        
        # Perform login
        login_url = login(username, password, response.headers.get('Location', ''))
        response = session.get(login_url)
        
        return session, response
        
    except (requests.Timeout, requests.RequestException) as e:
        raise NetworkError(f"Network error: {str(e)}")
    except Exception as e:
        raise LoginError(f"EAMIS login failed: {str(e)}")

def libic_login(username, password, session=None):
    """
    Login to library IC system.
    
    Args:
        username (str): User's login username
        password (str): User's login password
        session (requests.Session, optional): Existing session to use
        
    Returns:
        tuple: (requests.Session, None)
        
    Raises:
        LoginError: If login fails
        NetworkError: If network issues occur
    """
    try:
        session = session or get_session()
        
        # Initialize session
        session.get(LIBIC_URL)
        session.get(f'{LIBIC_URL}/ic-web/auth/userInfo')
        
        # Get authentication address
        headers = {'lan': '1', 'Referer': LIBIC_URL}
        response = session.get(
            f"{LIBIC_URL}/ic-web/auth/address"
            f"?finalAddress={LIBIC_URL}"
            f"&errPageUrl={LIBIC_URL}/#/error"
            "&manager=false&consoleType=16",
            verify=False,
            headers=headers
        )
        
        refered = json.loads(response.text).get('data', '')
        if not refered.startswith(f'{LIBIC_URL}/authcenter/toLoginPage'):
            raise LoginError("Invalid LIBIC response")
        
        # Follow redirect and login
        del headers['lan']
        response = session.get(refered, verify=False, allow_redirects=False, headers=headers)
        login_url = login(username, password, response.headers.get('Location', ''))
        
        response = session.get(
            login_url,
            timeout=TIMEOUT,
            data={'Upgrade-Insecure-Requests': 1}
        )
        
        # Verify login success
        response = session.get(f"{LIBIC_URL}/ic-web/auth/userInfo")
        if "查询成功" not in response.text:
            raise LoginError("Login verification failed")
            
        return session, None
        
    except (requests.Timeout, requests.RequestException) as e:
        raise NetworkError(f"Network error: {str(e)}")
    except Exception as e:
        raise LoginError(f"LIBIC login failed: {str(e)}")

def load_cached_password(username):
    """Load password from cache file if it exists."""
    try:
        if os.path.exists("passwords.list"):
            with open("passwords.list", 'r') as file:
                for line in file:
                    if line.startswith(username):
                        return line.split('\t')[-1].rstrip()
    except Exception:
        pass  # Silently fail if cache read fails
    return None

def save_password_to_cache(username, password):
    """Save password to cache file."""
    try:
        with open("passwords.list", "a") as file:
            file.write(f"\n{username}\t{password}")
    except Exception:
        pass  # Silently fail if cache write fails

if __name__ == "__main__":
    try:
        # Get username
        username = input("USERNAME: ")
        password = load_cached_password(username)
        
        if not password:
            password = getpass.getpass("PASSWORD: ")
            save_password_to_cache(username, password)
        else:
            print("Getting password from cache...")
        
        # Try a test login
        url = 'https://sso.nankai.edu.cn/sso/login?service=https://dzpz.nankai.edu.cn'
        result = login(username, password, url)
        print(result)
        
    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
    except NetworkError as e:
        print(f"Network error: {e}")
    except LoginError as e:
        print(f"Login error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
