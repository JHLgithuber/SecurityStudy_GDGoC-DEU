import json
import time

import socketio
import asyncio
import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import Crypto
from Crypto.Util.Padding import pad, unpad

sio = socketio.AsyncClient()  # 비동기로 작동하도록 AsyncClient 사용


@sio.on('connect')  # 비동기 connect 이벤트
async def on_connect():
    print('Connected to server!')



@sio.on('ping')  # ping 이벤트 처리
async def on_ping():
    await sio.emit('pong')  # pong 이벤트 보내기


@sio.on('pong')  # pong 이벤트 처리
async def on_pong(data):
    print(data)


@sio.on('disconnect')  # disconnect 이벤트 처리
async def on_disconnect():
    print('Disconnected from server!')

public_key_dict=dict()
rsa_key=RSA.generate(2048)
@sio.on('publickey_unicast')
async def on_publickey_unicast(data):
    data=data.split(":", maxsplit=1)
    public_key_dict[data[0]]=data[1]
    print(f"수신자 {data[0]}의 공개키를 수신했습니다.")

@sio.on('publickey_request')
async def on_publickey_request():
    public_key=rsa_key.publickey().publickey().export_key().decode('utf-8')
    await sio.emit("publickey_unicast",public_key)

async def encrypt(plaintext):
    # 공개키 요청
    await sio.emit("publickey_request")
    await sio.sleep(1)
        
    encrypt_datas = list()
    plaintext = plaintext.encode('utf-8')
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_ECB)
    padded_data = pad(plaintext, AES.block_size)
    encrypted_data_byAES = cipher_aes.encrypt(padded_data).hex()

    for public_key_dest in public_key_dict.keys():
        encrypt_data = dict()
        try:
            recipient_key = RSA.import_key(public_key_dict[public_key_dest])
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            enc_session_key = cipher_rsa.encrypt(aes_key).hex()

            encrypt_data["destination"] = public_key_dest
            encrypt_data["enc_session_key"] = enc_session_key
            encrypt_data["encrypted_data"] = encrypted_data_byAES
            encrypt_datas.append(encrypt_data)
            print(f"수신자 {public_key_dest}에 대한 암호화 완료")
        except Exception as e:
            print(f"수신자 {public_key_dest}에 대한 암호화 실패: {str(e)}")
            continue

    return json.dumps(encrypt_datas)

async def decrypt(ciphertext):
    ciphertext=json.loads(ciphertext)
    for decrypt_data in ciphertext:
        if decrypt_data["destination"]==id:
            private_key = RSA.import_key(rsa_key.export_key())
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(bytes.fromhex(decrypt_data["enc_session_key"]))
            cipher_aes = AES.new(aes_key, AES.MODE_ECB)
            decrypted_data_byAES = cipher_aes.decrypt(bytes.fromhex(decrypt_data["encrypted_data"]))
            plaintext = unpad(decrypted_data_byAES, AES.block_size).decode('utf-8')
            return plaintext
    return "ERROR: No matching destination found."



@sio.on('message_broadcast')  # message_broadcast 이벤트 처리
async def on_message_broadcast(data):
    try:
        sender, message = data.split(":", 1)
        decrypted_data = await decrypt(message)
        print(f"From {sender}: {decrypted_data}")
    except ValueError:
        print(f"Invalid message format from {sender}: {message}")
    except json.JSONDecodeError:
        print(f"Invalid JSON format from {sender}: {message}")

async def input_terminal():
    while True:
        # 동기 input을 비동기코드에서 실행
        user_input = await asyncio.to_thread(input, "> ")

        # 입력값에 따라 서버로 이벤트 전송
        if user_input.lower() == "ping":
            await sio.emit("ping")
        else:
            encrypted_data= await encrypt(user_input)
            await sio.emit("message_broadcast", encrypted_data)

def generate_random_name():
    adjectives = [
        "행복한", "즐거운", "귀여운", "멋진", "씩씩한", "용감한", "현명한", "똑똑한",
        "날쌘", "신나는", "재미있는", "활발한", "상냥한", "친절한", "꼼꼼한", "차분한",
        "열정적인", "신비한", "화려한", "단순한", "따뜻한", "시원한", "포근한", "배고픈",
        "졸린", "든든한", "엉뚱한", "깜찍한", "유쾌한", "싱그러운", "달콤한", "아기자기한"
    ]

    nouns = [
        "판다", "고양이", "강아지", "토끼", "부엉이", "사자", "독수리", "펭귄",
        "거북이", "기린", "코끼리", "돌고래", "참새", "호랑이", "곰", "여우",
        "다람쥐", "햄스터", "앵무새", "공룡", "고래", "물개", "사슴", "양",
        "악어", "팽귄", "원숭이", "코알라", "캥거루", "얼룩말", "하마", "수달"
    ]

    suffixes = [
        "님", "쿤", "짱", "킹", "프렌드", "마스터", "히어로", "챔피언",
        "아티스트", "천사", "전사", "master", "나인", "프로", "고수"
    ]

    # 기본 이름 생성
    name = random.choice(adjectives) + "_" + random.choice(nouns)

    # 20% 확률로 접미사 추가
    if random.random() < 0.2:
        name += "_" + random.choice(suffixes)

    return name

id=None
async def main(name=generate_random_name()):
    global id
    print(f"Name: {name}")
    print("Public key:\n", rsa_key.publickey().export_key().decode('utf-8'))
    print("Private key:\n", rsa_key.export_key().decode('utf-8'))
    try:
        # 서버에 연결 시도
        await sio.connect('http://localhost:5000')
        time.sleep(1)
        await sio.emit("rename", name)  # rename 이벤트 전송
        print(f"My name is {name}")
        id=name

        # 이벤트 대기와 입력을 동시 실행
        await asyncio.gather(sio.wait(), input_terminal())

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        await sio.disconnect()  # 연결 해제


if __name__ == '__main__':
    asyncio.run(main())