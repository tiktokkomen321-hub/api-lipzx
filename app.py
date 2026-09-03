from flask import Flask, request, jsonify
from flask_cors import CORS  # Tambahkan import CORS
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from protobuf_decoder.protobuf_decoder import Parser
import codecs
import time
from datetime import datetime
import urllib3
import base64
import concurrent.futures
import threading
import os
import re

# Disable only the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ---------------- CORS CONFIGURATION ---------------- #
# Enable CORS for all routes
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Manual CORS headers as fallback
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# ---------------- KEYS ---------------- #
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)

REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","EU": "en","RU": "ru","NA": "en","SAC": "es","BR": "pt","CIS": "ru"}
REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/",
    "ID": "https://clientbp.ggblueshark.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "ME": "https://clientbp.common.ggbluefox.com/",
    "VN": "https://clientbp.ggblueshark.com/",
    "TH": "https://clientbp.common.ggbluefox.com/",
    "RU": "https://clientbp.ggblueshark.com/",
    "BD": "https://clientbp.ggblueshark.com/",
    "PK": "https://clientbp.ggblueshark.com/",
    "SG": "https://clientbp.ggblueshark.com/",
    "NA": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "EU": "https://clientbp.ggblueshark.com/",
    "TW": "https://clientbp.ggblueshark.com/",
    "CIS": "https://clientbp.ggblueshark.com/"
}

# ---------------- RARE PATTERN DETECTION ---------------- #
PATTERNS = {
    "R4": [r"(\d)\1{3,}", 3], "R3": [r"(\d)\1\1(\d)\2\2", 2],
    "S5": [r"(12345|23456|34567|45678|56789)", 4], "S4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "P6": [r"^(\d)(\d)(\d)\3\2\1$", 5], "P4": [r"^(\d)(\d)\2\1$", 3],
    "SPH": [r"(69|420|1337|007)", 4], "SPM": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QD": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MH": [r"^(\d{2,3})\1$", 3], "MM": [r"(\d{2})0\1", 2], "GD": [r"1618|0618", 3]
}

def detect_rare_pattern(uid):
    """
    Detect rare patterns in UID
    Returns: (is_rare, pattern_name, score, matched_patterns)
    """
    uid_str = str(uid)
    max_score = 0
    matched_patterns = []
    
    for pattern_name, (pattern, score) in PATTERNS.items():
        matches = re.findall(pattern, uid_str)
        if matches:
            matched_patterns.append({
                "name": pattern_name,
                "score": score,
                "match": matches[0] if matches else None
            })
            if score > max_score:
                max_score = score
    
    if matched_patterns:
        # Sort by score descending
        matched_patterns.sort(key=lambda x: x["score"], reverse=True)
        return True, matched_patterns[0]["name"], max_score, matched_patterns
    
    return False, None, 0, []

# ---------------- OPTIMIZATION ---------------- #
OPTIMIZATION = {
    'timeout': 30,
    'max_retries': 3
}

# Global exit flag
EXIT = False

def get_region(language_code: str) -> str:
    return REGION_LANG.get(language_code)

def get_region_url(region_code: str) -> str:
    return REGION_URLS.get(region_code, None)

# Thread-local storage for requests
thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
        
    return thread_local.session

# ---------------- IP Spoofer ---------------- #
class FastIPSpoofer:
    _ip_cache = []
    _cache_index = 0
    
    @classmethod
    def get_ip_fast(cls):
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

# ---------------- WAF Bypass ---------------- #
class WAFBypass:
    @staticmethod
    def get_ua():
        user_agents = [
            "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "GarenaMSDK/4.0.19P8(Redmi Note 8 ;Android 10;en;US;)",
            "GarenaMSDK/4.0.19P8(Pixel 3 ;Android 11;en;US;)"
        ]
        return random.choice(user_agents)

# ---------------- PROTOBUF ENCODING ---------------- #
def EnC_Vr(N):
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

build_proto = CrEaTe_ProTo

# ---------------- AES ENCRYPTION ---------------- #
def E_AEs(Pc):
    Z = bytes.fromhex(Pc)
    key_bytes = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    K = AES.new(key_bytes, AES.MODE_CBC, iv)
    R = K.encrypt(pad(Z, AES.block_size))
    return bytes.fromhex(R.hex())

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key_bytes = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

aes_encrypt = encrypt_api

# ---------------- NAME / PASSWORD ---------------- #
def generate_random_name(name_prefix):
    characters = string.ascii_letters + string.digits
    return name_prefix + ''.join(random.choice(characters) for _ in range(6)).upper()

def generate_custom_password(password_prefix="SPIDER"):
    characters = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(9)).upper()
    return f"{password_prefix}-{random_part}-CORE"

# ---------------- Account creation flow ---------------- #
def get_token(uid, password, region, account_name, password_prefix, is_ghost=False):
    if EXIT:
        return None
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "User-Agent": WAFBypass.get_ua(),
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": key, "client_id": "100067"}
        session = get_session()
        response = session.post(url, headers=headers, data=body, timeout=OPTIMIZATION['timeout'], verify=False)
        
        if response.status_code == 200 and 'open_id' in response.json():
            open_id = response.json()['open_id']
            access_token = response.json()["access_token"]
            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = ""
            for i in range(len(open_id)):
                encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
            field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost=False):
    if EXIT:
        return None
    try:
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
        elif region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorRegister"
        else:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
        name = generate_random_name(account_name)
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "ReleaseVersion": "OB54", 
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1", 
            "Accept-Encoding": "deflate, gzip",
            "X-Unity-Version": "2022.3.47f1.",
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
        lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field, 15: lang_code, 16: 1, 17: 1}
        payload_bytes = build_proto(payload)
        encrypted_payload = aes_encrypt(payload_bytes.hex())
        session = get_session()
        session.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False, timeout=OPTIMIZATION['timeout'])
        
        login_result = major_login(uid, password, access_token, open_id, region, is_ghost)
        account_id = login_result.get("account_id", "N/A")
        jwt_token = login_result.get("jwt_token", "")
        
        if account_id != "N/A":
            if not is_ghost and jwt_token and region.upper() != "BR":
                try:
                    force_region_bind(region, jwt_token)
                except:
                    pass
            
            # Detect rare pattern
            is_rare, rare_pattern, rare_score, matched_patterns = detect_rare_pattern(account_id)
            
            return {
                "uid": uid, 
                "password": password, 
                "name": name,
                "region": "GHOST" if is_ghost else region, 
                "status": "success",
                "account_id": account_id, 
                "jwt_token": jwt_token,
                "is_rare": is_rare,
                "rare_pattern": rare_pattern,
                "rare_score": rare_score,
                "matched_patterns": matched_patterns
            }
    except:
        pass
    return None

def major_login(uid, password, access_token, open_id, region, is_ghost=False):
    try:
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        elif region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "ReleaseVersion": "OB54", 
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1", 
            "Accept-Encoding": "deflate, gzip",
            "X-Unity-Version": "2022.3.47f1.",
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
        data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        d = encrypt_api(data.hex())
        session = get_session()
        response = session.post(url, headers=headers, data=bytes.fromhex(d), verify=False, timeout=OPTIMIZATION['timeout'])
        
        if response.status_code == 200 and len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            payload_part = parts[1]
                            padding = 4 - len(payload_part) % 4
                            if padding != 4:
                                payload_part += '=' * padding
                            decoded = base64.urlsafe_b64decode(payload_part)
                            data = json.loads(decoded)
                            account_id = data.get('account_id') or data.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except:
                        pass
        return {"account_id": "N/A", "jwt_token": ""}
    except:
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token):
    """Force region binding for non-BR regions"""
    try:
        if region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/ChooseRegion"
        else:
            url = "https://loginbp.ggblueshark.com/ChooseRegion"
        
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        proto_data = build_proto({1: region_code})
        encrypted_data = encrypt_api(proto_data.hex())
        payload = bytes.fromhex(encrypted_data)
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Authorization': f"Bearer {jwt_token}",
            "Accept-Encoding": "deflate, gzip",
            "X-Unity-Version": "2022.3.47f1.",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54",
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            'X-Forwarded-For': spoofed_ip,
            'X-Real-IP': spoofed_ip,
        }
        
        session = get_session()
        session.post(url, data=payload, headers=headers, verify=False, timeout=30)
    except:
        pass

# ---------------- Account creation wrapper ---------------- #
def create_single_account(args):
    name_prefix, region, password_prefix, is_ghost = args
    max_retries = OPTIMIZATION['max_retries']
    for attempt in range(max_retries):
        try:
            result = create_acc(region, name_prefix, password_prefix, is_ghost)
            if result and result.get('uid') and result.get('password') and result.get('status') == "success":
                return result
            time.sleep(1)
        except Exception as e:
            time.sleep(1)
    return None

def create_acc(region, name_prefix, password_prefix, is_ghost=False):
    """
    Complete account creation flow
    """
    password = generate_custom_password(password_prefix)
    session = get_session()
    
    # Step 1: Guest Register
    url = "https://ffmconnect.ppmainecoonghj.com/api/v2/oauth/guest:register"
    payload = {
        "app_id": 100067,
        "client_type": 2,
        "password": AGE,
        "source": 2
    }
    
    spoofed_ip = FastIPSpoofer.get_ip_fast()
    
    headers = {
        "User-Agent": WAFBypass.get_ua(),
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Accept-Encoding": "deflate, gzip",
        "X-Unity-Version": "2022.3.47f1.",
        "Connection": "Keep-Alive",
        "X-Forwarded-For": spoofed_ip,
        "X-Real-IP": spoofed_ip,
    }

    try:
        response = session.post(url, headers=headers, json=payload, timeout=OPTIMIZATION['timeout'])
        resp_json = response.json()
        uid = resp_json.get('data', {}).get('uid')
        if not uid:
            return None
        return get_token(uid, password, region, name_prefix, password_prefix, is_ghost)
    except Exception as e:
        return None

# ---------------- FLASK API ---------------- #
@app.route('/gen', methods=['GET', 'OPTIONS'])
def generate_accounts():
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    # Get parameters
    name = request.args.get('name', 'HUSTLER')
    count = request.args.get('count', '1')
    region = request.args.get('region', 'IND')
    password_prefix = request.args.get('password_prefix', 'SPIDER')
    is_ghost = request.args.get('ghost', 'false').lower() == 'true'
    detect_rare = request.args.get('detect_rare', 'true').lower() == 'true'
    
    # Validate and convert count - NO LIMIT
    try:
        count = int(count)
        if count < 1:
            count = 1
        # Remove max limit
    except:
        count = 1
    
    # Validate region
    region = region.upper()
    if region not in REGION_LANG and not is_ghost:
        region = "IND"
    
    print(f"Starting creation of {count} accounts for region {region} with name prefix {name}")
    
    # Use thread pool with configurable workers
    max_workers = min(count, 10)  # Max 10 concurrent, but can be adjusted
    
    # Create accounts with retry mechanism
    results = []
    rare_accounts = []
    attempts = 0
    max_total_attempts = count * 3  # Reduce retry attempts for speed
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        while len(results) < count and attempts < max_total_attempts:
            needed = count - len(results)
            current_batch = min(needed, max_workers)
            
            futures = []
            for i in range(current_batch):
                future = executor.submit(create_single_account, (name, region, password_prefix, is_ghost))
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                attempts += 1
                result = future.result()
                if result and result.get('status') == "success":
                    # Check if rare and collect separately
                    if detect_rare and result.get('is_rare', False):
                        rare_accounts.append(result)
                        print(f"🔥 RARE ACCOUNT FOUND! Account ID: {result['account_id']}, Pattern: {result.get('rare_pattern', 'Unknown')}, Score: {result.get('rare_score', 0)}")
                    
                    results.append(result)
                    print(f"Successfully created account {len(results)}/{count}: UID {result['uid']}, AccountID: {result.get('account_id', 'N/A')}")
                
                if len(results) >= count:
                    break
            
            if len(results) < count:
                time.sleep(1)  # Reduced sleep time
    
    # Prepare response
    response_data = {
        "success": True,
        "total_requested": count,
        "total_created": len(results),
        "accounts": results,
        "attempts_made": attempts,
        "rare_count": len(rare_accounts) if detect_rare else 0
    }
    
    if detect_rare and rare_accounts:
        response_data["rare_accounts"] = rare_accounts
    
    print(f"Completed: Created {len(results)} accounts out of {count} requested")
    return jsonify(response_data)

@app.route('/patterns', methods=['GET', 'OPTIONS'])
def get_patterns():
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    """Get list of all rare patterns"""
    patterns_info = []
    for name, (pattern, score) in PATTERNS.items():
        patterns_info.append({
            "name": name,
            "pattern": pattern,
            "score": score
        })
    return jsonify({
        "total_patterns": len(patterns_info),
        "patterns": patterns_info
    })

@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    return jsonify({
        "message": "FreeFire Account Generator API - Unlimited Generation",
        "endpoint": "/gen?name=NAME&count=COUNT&region=REGION&password_prefix=PREFIX&ghost=BOOLEAN&detect_rare=BOOLEAN",
        "max_count": "UNLIMITED",
        "available_regions": list(REGION_LANG.keys()),
        "features": {
            "rare_pattern_detection": "Detects rare UID patterns (R4, R3, S5, S4, P6, P4, SPH, SPM, QD, MH, MM, GD, PAIR3, PAIRX, ALT, ALT8, TAIL0, HEAD1, BLOCK, STEP2, MIX)",
            "ghost_mode": "Create GHOST region accounts",
            "unlimited_generation": "No limit on account generation",
            "cors_enabled": "API can be accessed from any domain"
        },
        "note": "Complete account creation with ALL steps: register -> token -> major register -> major login -> getlogindata",
        "patterns_endpoint": "/patterns - View all rare patterns"
    })

@app.route('/health', methods=['GET', 'OPTIONS'])
def health():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    return jsonify({"status": "healthy", "message": "API is running"})

# For Vercel - WSGI compatible
def application(environ, start_response):
    return app(environ, start_response)

# For local development
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)
