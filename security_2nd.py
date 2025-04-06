import hashlib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import secrets
import re


class Toolbox:  # 암호학자의 도구상자
    def __init__(self):
        self.counter = 0
        self.seed = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")


    def deterministic_rand(self, n):
        output = b''
        while len(output) < n:
            data = self.seed + self.counter.to_bytes(4, 'big')
            output += hashlib.sha256(data).digest()
            self.counter += 1
        return output[:n]

    def aes_encryption(self, value, key):
        # key 처리: 문자열이면 hex로 변환, 이미 bytes면 그대로 사용
        key_bytes = bytes.fromhex(key) if isinstance(key, str) else key

        # 평문(value) 처리: 문자열이면 utf-8로 인코딩, 그렇지 않으면 그대로 사용
        data_bytes = value.encode('utf-8') if isinstance(value, str) else value

        cipher = AES.new(key_bytes, AES.MODE_ECB)
        padded_data = space_pad(data_bytes)
        encrypted = cipher.encrypt(padded_data)
        result = encrypted.hex()

        print("암호화 결과:\n", result)
        return result

    def aes_decryption(self, value, key):
        # key 처리
        key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
        # 복호화할 비문(value) 처리: hex 문자열이면 변환, 그렇지 않으면 그대로 사용
        ct_bytes = bytes.fromhex(value) if isinstance(value, str) else value

        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(ct_bytes)
        result = space_unpad(decrypted_bytes).decode('utf-8', errors='ignore')

        print("복호화 결과:\n", result)
        return result

    def rsa_key_making(self, hex_seed, bits=1024):
        self.seed = bytes.fromhex(hex_seed)


        print("RSA 키 생성 중...")
        rsa_key = RSA.generate(bits=bits, randfunc=self.deterministic_rand)

        # 생성된 키를 PEM 형식에서 한 줄 문자열로 변경 (줄바꿈 제거)
        decryption_key = rsa_key.export_key().decode('utf-8').replace('\n', '')
        encryption_key = rsa_key.public_key().export_key().decode('utf-8').replace('\n', '')

        print("\n한 줄 형식 비밀키:\n", decryption_key)
        print("\n한 줄 형식 공개키:\n", encryption_key)

        return rsa_key

    def rsa_encryption(self, plaintext: str, single_line_public_key: str) -> bytes:
        """
        한 줄짜리 공개키(single_line_public_key)를 수신하여,
        메시지(plaintext)를 RSA로 암호화한 예시입니다.
        """
        # 한 줄짜리 키 -> PEM 복원
        public_key_pem = single_line_to_multiline_pem(single_line_public_key)

        # PyCryptodome의 RSA.import_key로 PEM 키를 읽어들입니다.
        rsa_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_v1_5.new(rsa_key, randfunc=self.deterministic_rand)
        encrypted_bytes = cipher.encrypt(plaintext.encode("utf-8"))
        print("암호화 결과: ", encrypted_bytes.hex())
        return encrypted_bytes

    def rsa_decryption(self, ciphertext_hex: str, single_line_private_key: str) -> str:
        """
        한 줄짜리 비밀키(single_line_private_key)를 수신하여,
        RSA 암호문(ciphertext_hex)을 복호화한 예시입니다.
        """
        private_key_pem = single_line_to_multiline_pem(single_line_private_key)
        rsa_key = RSA.import_key(private_key_pem)

        # PKCS1_v1_5 또는 PKCS1_OAEP를 선택적으로 사용 가능
        cipher = PKCS1_v1_5.new(rsa_key, randfunc=self.deterministic_rand)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        plaintext_bytes = cipher.decrypt(ciphertext_bytes, None)
        plan_text = plaintext_bytes.decode("utf-8", errors='replace')

        # UTF-8로 디코딩(문자열이 아닌 바이너리라면 적절히 처리)
        print("복호화 결과: ", plan_text)
        return plan_text

    def hash(self, value):  # 일방향 해시 함수
        secure_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()
        print("해시값:\n", secure_hash)
        return secure_hash

    def random(self):  # 의사 난수 생성
        random_hex = secrets.token_hex(32)
        print("랜덤 값 (hex):\n", random_hex)
        return random_hex

def single_line_to_multiline_pem(single_line_key: str) -> str:
    """
    한 줄로 주어진 PEM 문자열을 다시 여러 줄짜리 PEM으로 복원합니다.
    (예: '-----BEGIN PUBLIC KEY-----MIIBIjANBg...-----END PUBLIC KEY-----')
    """
    # 공백이나 줄바꿈이 섞여 있을 수도 있으므로, 함께 제거
    clean_str = single_line_key.replace('\n', '').replace('\r', '')

    # BEGIN/END 라벨을 정규식으로 찾기
    # PEM의 Base64 영역을 세 그룹으로 나누어 추출: 헤더, Base64 부분, 푸터
    pattern = r'(-----BEGIN [^-]+-----)([A-Za-z0-9+/=\s]+)(-----END [^-]+-----)'
    match = re.search(pattern, clean_str)
    if not match:
        raise ValueError("PEM 형식에 맞지 않는 문자열입니다.")

    header = match.group(1)
    base64_body = match.group(2).strip().replace(' ', '')
    footer = match.group(3)

    # Base64 부분을 64자 단위로 줄바꿈
    chunked = '\n'.join([base64_body[i:i + 64] for i in range(0, len(base64_body), 64)])

    # PEM 형식 복원
    multiline_pem = header + '\n' + chunked + '\n' + footer + '\n'
    return multiline_pem


def input_key_and_message(key_prompt, text_prompt):
    key = input(f"{key_prompt}를 입력하세요:\n")
    value = input(f"{text_prompt}를 입력하세요:\n")
    return key, value


# 공백으로 패딩하는 함수
def space_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + b' ' * pad_len

# 패딩 제거하는 함수 (우측 공백 제거)
def space_unpad(data):
    return data.rstrip(b' ')


if __name__ == "__main__":
    toolbox = Toolbox()
    while True:
        print("\n\n")
        print("1: 대칭키 암호화")
        print("2: 대칭키 복호화")
        print("3: 공캐키 쌍 생성")
        print("4: 공개키 암호화")
        print("5: 공개키 복호화")
        print("6: 일방향 해시 함수")
        print("7: 의사 난수 생성")
        menu_select = input("선택: ")

        try:
            if menu_select == "1":
                print("\033[1m" + "대칭키 암호화" + "\033[0m")
                # 대칭키 암호화: 키는 hex, 평문은 일반 문자열
                hex_key, plain_text = input_key_and_message("대칭키", "평문")
                toolbox.aes_encryption(plain_text, hex_key)

            elif menu_select == "2":
                print("\033[1m" + "대칭키 복호화" + "\033[0m")
                # 대칭키 복호화: 키는 hex, 암호문은 hex 문자열
                hex_key, cipher_text = input_key_and_message("대칭키", "비문 (hex)")
                toolbox.aes_decryption(cipher_text, hex_key)

            elif menu_select == "3":
                print("\033[1m" + "공캐키 쌍 생성" + "\033[0m")
                seed = input("시드를 hex 값으로 입력하세요:\n")
                toolbox.rsa_key_making(seed)

            elif menu_select == "4":
                print("\033[1m" + "공개키 암호화" + "\033[0m")
                # 공개키 암호화: 키는 PEM 문자열, 평문은 일반 문자열
                key_text, plain_text = input_key_and_message("공개키", "평문")
                toolbox.rsa_encryption(plain_text, key_text)

            elif menu_select == "5":
                print("\033[1m" + "공개키 복호화" + "\033[0m")
                # 공개키 복호화: 키는 PEM 문자열, 암호문은 hex 문자열
                key_text, cipher_text = input_key_and_message("비밀키", "비문 (hex)")
                toolbox.rsa_decryption(cipher_text, key_text)

            elif menu_select == "6":
                print("\033[1m" + "일방향 해시 함수" + "\033[0m")
                data = input("데이터를 입력하세요:\n")
                toolbox.hash(data)

            elif menu_select == "7":
                print("\033[1m" + "의사 난수 생성" + "\033[0m")
                toolbox.random()

            else:
                print("\033[1m" + "잘못된 메뉴 선택" + "\033[0m")

        except ValueError as e:
            print("\033[91m오류 발생:", e, "\033[0m")  # 빨간색으로 오류 메시지 출력

        except KeyboardInterrupt:
            break

        except Exception as e:
            print("\033[91m모르는 오류 발생:", e, "\033[0m")
