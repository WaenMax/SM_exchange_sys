import argparse
from gmssl.sm2 import CryptSM2
import win32crypt  # 用于DPAPI加密/解密

def dpapi_decrypt_key(enc_key_bytes: bytes) -> bytes:
    """
    使用Windows DPAPI解密本地加密的SM4密钥。
    """
    decrypted = win32crypt.CryptUnprotectData(enc_key_bytes, None, None, None, 0)[1]
    return decrypted

def main():
    parser = argparse.ArgumentParser(description="用SM2公钥加密SM4密钥（密钥文件）")
    parser.add_argument('--pk_file', required=True, help="SM2公钥文件（PEM或纯Hex字符串）")
    parser.add_argument('--key_file', required=True, help="本地加密的SM4密钥文件（使用DPAPI加密）")
    parser.add_argument('--out', required=True, help="输出加密后的密钥文件")

    args = parser.parse_args()

    # 1. 读取本地加密的SM4密钥
    with open(args.key_file, 'rb') as f:
        enc_key_bytes = f.read()
    sm4_key = dpapi_decrypt_key(enc_key_bytes)

    # 2. 读取SM2公钥
    with open(args.pk_file, 'r') as f:
        public_key = f.read().strip()

    # 3. 使用SM2公钥加密SM4密钥
    sm2_crypt = CryptSM2(public_key=public_key, private_key=None)
    encrypted_sm4_key = sm2_crypt.encrypt(sm4_key)

    # 4. 输出加密后的SM4密钥文件
    with open(args.out, 'wb') as f:
        f.write(encrypted_sm4_key)

    print(f"SM4密钥加密完成，输出文件：{args.out}")

if __name__ == "__main__":
    main()
