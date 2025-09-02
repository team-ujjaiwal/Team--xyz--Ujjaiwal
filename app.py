from flask import Flask, request, jsonify
import requests
import json
import threading
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import google.protobuf as protobuf
import CWSpam_count_pb2
import time
import random

app = Flask(__name__)

# Encryption functions from byte.py integrated directly
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ac', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    
    x = x/128 
    if x > 128:
        x = x/128
        if x > 128:
            x = x/128
            if x > 128:
                x = x/128
                strx = int(x)
                y = (x - strx) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - strx) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
        else:
            strx = int(x)
            y = (x - strx) * 128
            stry = str(int(y))
            z = (y - int(stry)) * 128
            strz = str(int(z))
            return dec[int(z)] + dec[int(y)] + xxx[int(x)] 
    else:
        strx = int(x)
        if strx == 0:
            y = (x - strx) * 128
            inty = int(y)
            return xxx[inty]
        else:
            y = (x - strx) * 128
            stry = str(int(y))
            return dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def load_tokens(region):
    try:
        if region == "IND":
            with open("spam_ind.json", "r") as f:
                data = json.load(f)
                tokens = [item["token"] for item in data]
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("spam_br.json", "r") as f:
                data = json.load(f)
                tokens = [item["token"] for item in data]
        else:
            with open("spam_bd.json", "r") as f:
                data = json.load(f)
                tokens = [item["token"] for item in data]
        return tokens
    except Exception as e:
        print(f"Error loading tokens for {region}: {e}")
        return []

def get_region_url(server_name, endpoint):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com"
    else:
        url = "https://clientbp.ggblueshark.com"
    
    return f"{url}/{endpoint}"

# List of user agents to rotate
USER_AGENTS = [
    "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
    "Dalvik/2.1.0 (Linux; U; Android 10; SM-G981B Build/QP1A.190711.020)",
    "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 5 Build/RQ3A.210805.001.A1)",
    "Dalvik/2.1.0 (Linux; U; Android 12; SM-S908E Build/SP1A.210812.016)"
]

def get_headers(token):
    return {
        "Expect": "100-continue",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "16",
        "User-Agent": random.choice(USER_AGENTS),
        "Host": "clientbp.ggblueshark.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }

def get_player_info(uid, region, token):
    """Get actual player information using GetPlayerPersonalShow endpoint"""
    try:
        # Add delay to avoid rate limiting
        time.sleep(random.uniform(1, 2))
        
        # Create payload for GetPlayerPersonalShow
        encrypted_id = Encrypt_ID(uid)
        payload = f"08{encrypted_id}10a7c4839f1e1801"
        encrypted_payload = encrypt_api(payload)
        
        url = get_region_url(region, "GetPlayerPersonalShow")
        headers = get_headers(token)
        
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=10)
        
        if response.status_code == 200:
            # Parse the protobuf response
            player_info = CWSpam_count_pb2.Info()
            player_info.ParseFromString(response.content)
            return player_info
        elif response.status_code == 429:
            print(f"Rate limited when fetching player info")
            return None
        else:
            print(f"Failed to get player info: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error getting player info: {e}")
        return None

def send_friend_request_with_retry(uid, token, region, results, max_retries=3):
    for attempt in range(max_retries):
        try:
            # Add random delay with exponential backoff
            delay = random.uniform(1, 3) * (attempt + 1)
            time.sleep(delay)
            
            encrypted_id = Encrypt_ID(uid)
            payload = f"08a7c4839f1e10{encrypted_id}1801"
            encrypted_payload = encrypt_api(payload)

            url = get_region_url(region, "RequestAddingFriend")
            headers = get_headers(token)

            response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=10)

            if response.status_code == 200:
                results["success"] += 1
                return
            elif response.status_code == 429:
                print(f"Rate limited, waiting longer... Attempt {attempt + 1}")
                time.sleep(5)  # Longer wait for rate limits
                continue
            else:
                results["failed"] += 1
                return
                
        except Exception as e:
            print(f"Error on attempt {attempt + 1}: {e}")
            if attempt == max_retries - 1:
                results["failed"] += 1

@app.route("/send_requests", methods=["GET"])
def send_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "IND").upper()

    if not uid:
        return jsonify({"error": "uid parameter is required"}), 400

    tokens = load_tokens(region)
    if not tokens:
        return jsonify({"error": f"No tokens found for region {region}"}), 500

    # Get actual player information using the first token
    player_info = get_player_info(uid, region, tokens[0])
    
    if not player_info:
        return jsonify({"error": "Failed to get player information. Server may be rate limiting."}), 500

    MAX_CONCURRENT = 20  # Reduced from 110 to avoid overwhelming the server
    tokens_to_use = tokens[:MAX_CONCURRENT]
    
    results = {"success": 0, "failed": 0}
    threads = []

    for token in tokens_to_use:
        thread = threading.Thread(target=send_friend_request_with_retry, 
                                 args=(uid, token, region, results))
        threads.append(thread)
        thread.start()
        
        # Limit concurrent threads to avoid rate limiting
        if len(threading.enumerate()) > 10:  # Max 10 concurrent threads
            time.sleep(1)

    for thread in threads:
        thread.join()

    total_requests = results["success"] + results["failed"]
    status = 1 if results["success"] != 0 else 2

    response_data = {
        "success_count": results["success"],
        "failed_count": results["failed"],
        "PlayerNickname": player_info.AccountInfo.PlayerNickname,
        "PlayerLevel": player_info.AccountInfo.Levels,
        "PlayerLikes": player_info.AccountInfo.Likes,
        "PlayerRegion": player_info.AccountInfo.PlayerRegion,
        "status": status
    }

    return jsonify(response_data)

@app.route("/")
def index():
    return """
    <h1>Free Fire Friend Request Sender</h1>
    <p>Use the /send_requests endpoint with parameters:</p>
    <ul>
        <li>uid: Player ID (required)</li>
        <li>region: Server region (IND, BR, US, SAC, NA, etc.)</li>
    </ul>
    <p>Example: /send_requests?uid=6864208646&region=IND</p>
    """

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)