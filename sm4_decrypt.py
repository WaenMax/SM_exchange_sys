import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from gmssl.sm4 import CryptSM4, SM4_DECRYPT

def sm4_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV 必须为 16 字节")

    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_DECRYPT)
    plaintext = crypt_sm4.crypt_cbc(iv, data)
    # plaintext = unpad(padded_plaintext, 16)  # 去除 PKCS#7 填充
    return plaintext
def main():
    parser = argparse.ArgumentParser(description="使用本地保护的SM4密钥对文件解密")
    parser.add_argument('--key_file', required=True, help="本地加密的SM4密钥文件")
    # parser.add_argument('--password', required=True, help="本地密钥文件密码")
    parser.add_argument('--iv', required=True, help="16字节IV，16进制字符串")
    parser.add_argument('--input', required=True, help="待解密密文文件")
    parser.add_argument('--output', required=True, help="解密后明文文件")

    args = parser.parse_args()

    with open(args.key_file, 'rb') as f:
        enc_key_bytes = f.read()

    sm4_key = enc_key_bytes

    with open(args.input, 'rb') as f:
        ciphertext = f.read()

    iv_bytes = bytes.fromhex(args.iv)

    plaintext = sm4_cbc_decrypt(ciphertext, sm4_key, iv_bytes)

    with open(args.output, 'wb') as f:
        f.write(plaintext)

    print(f"文件解密完成，输出文件：{args.output}")

if __name__ == "__main__":
    main()
