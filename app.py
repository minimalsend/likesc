from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

# Constants
TARGET_LIKES = 100  # The number of likes we want to guarantee
MAX_RETRIES = 5     # Maximum retries for token fetching

# Encrypt a protobuf message
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# Create Like protobuf message
def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

# Create UID protobuf message
def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

# Encrypt UID protobuf
def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

# Fetch tokens from all JWT APIs with retries
async def fetch_all_tokens_with_retry():
    urls = [
        "https://showjwt.onrender.com/token"
    ]
    
    for attempt in range(MAX_RETRIES):
        try:
            all_tokens = []
            async with aiohttp.ClientSession() as session:
                tasks = [session.get(url) for url in urls]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    if isinstance(response, Exception):
                        continue
                    if response.status != 200:
                        continue
                    data = await response.json()
                    tokens = data.get("tokens", [])
                    if tokens:
                        all_tokens.extend(tokens)
            
            if all_tokens:
                return all_tokens
                
        except Exception as e:
            app.logger.error(f"Attempt {attempt + 1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(1)  # Wait before retrying
    
    app.logger.error("Failed to fetch tokens after all retries")
    return None

# Send a batch of like requests
async def send_batch_requests(encrypted_uid, tokens, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers_template = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for token in tokens:
                headers = headers_template.copy()
                headers['Authorization'] = f"Bearer {token}"
                tasks.append(session.post(url, data=edata, headers=headers))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            successful = 0
            for response in responses:
                if not isinstance(response, Exception) and response.status == 200:
                    successful += 1
            return successful
    except Exception as e:
        app.logger.error(f"Exception in send_batch_requests: {e}")
        return 0

# Get player info
def get_player_info(encrypted_uid, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
            
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        binary = response.content
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
            return None
        
        jsone = MessageToJson(decode)
        return json.loads(jsone)
    except Exception as e:
        app.logger.error(f"Error in get_player_info: {e}")
        return None

# Decode protobuf data into object
def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

async def process_like_request(uid, server_name):
    # Get initial info
    tokens = await fetch_all_tokens_with_retry()
    if not tokens:
        return {"error": "Failed to get tokens"}
        
    token = tokens[0]
    encrypted_uid = enc(uid)
    if not encrypted_uid:
        return {"error": "Encryption failed"}
        
    initial_info = get_player_info(encrypted_uid, server_name, token)
    if not initial_info:
        return {"error": "Failed to get initial player info"}
        
    before_like = int(initial_info.get('AccountInfo', {}).get('Likes', 0))
    player_name = str(initial_info.get('AccountInfo', {}).get('PlayerNickname', ''))
    player_uid = int(initial_info.get('AccountInfo', {}).get('UID', 0))
    
    # Determine the like endpoint
    if server_name == "IND":
        like_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_url = "https://clientbp.ggblueshark.com/LikeProfile"
    
    # Keep sending likes until we reach the target
    total_sent = 0
    attempts = 0
    max_attempts = 10  # Prevent infinite loops
    
    while total_sent < TARGET_LIKES and attempts < max_attempts:
        attempts += 1
        
        # Get fresh tokens for each attempt
        tokens = await fetch_all_tokens_with_retry()
        if not tokens:
            continue
            
        # Send a batch of requests
        batch_size = min(len(tokens), TARGET_LIKES - total_sent)
        successful = await send_batch_requests(
            encrypted_uid, 
            tokens[:batch_size], 
            like_url
        )
        
        total_sent += successful
        app.logger.info(f"Sent {successful} likes in this batch (total: {total_sent})")
        
        # Small delay between batches
        if total_sent < TARGET_LIKES:
            await asyncio.sleep(1)
    
    # Get final count
    final_info = get_player_info(encrypted_uid, server_name, token)
    if not final_info:
        return {"error": "Failed to get final player info"}
        
    after_like = int(final_info.get('AccountInfo', {}).get('Likes', 0))
    actual_likes_given = after_like - before_like
    
    return {
        "LikesGivenByAPI": actual_likes_given,
        "LikesBeforeCommand": before_like,
        "LikesafterCommand": after_like,
        "PlayerNickname": player_name,
        "UID": player_uid,
        "status": 1 if actual_likes_given > 0 else 2,
        "message": f"Successfully processed {actual_likes_given} likes" if actual_likes_given > 0 else "Failed to send likes"
    }

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()

    if not uid or not server_name:
        return jsonify({"error": "UID and region are required"}), 400

    try:
        # Run the async function in an event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(process_like_request(uid, server_name))
        loop.close()
        
        if "error" in result:
            return jsonify(result), 500
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)