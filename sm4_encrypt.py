import argparse
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

def dpapi_decrypt_key(encrypted_key_bytes: bytes) -> bytes:
    """
    使用 Windows DPAPI 解密 SM4 密钥
    """
    decrypted_data = win32crypt.CryptUnprotectData(encrypted_key_bytes, None, None, None, 0)
    return decrypted_data[1]  # 返回解密后的原始 SM4 密钥

def sm4_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV 必须为 16 字节")

    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    ciphertext = crypt_sm4.crypt_cbc(iv, data)
    return ciphertext

def main():
    parser = argparse.ArgumentParser(description="使用 Windows DPAPI 保护的 SM4 密钥对文件加密")
    parser.add_argument('--key_file', required=True, help="DPAPI 加密的 SM4 密钥文件路径")
    parser.add_argument('--iv', required=True, help="16字节 IV（16进制字符串）")
    parser.add_argument('--input', required=True, help="待加密明文文件路径")
    parser.add_argument('--output', required=True, help="加密后输出的密文文件路径")

    args = parser.parse_args()

    # 1. 读取 DPAPI 加密的 SM4 密钥
    with open(args.key_file, 'rb') as f:
        encrypted_key_bytes = f.read()

    try:
        sm4_key = dpapi_decrypt_key(encrypted_key_bytes)
    except Exception as e:
        print(f"DPAPI 解密失败，请确保运行在加密该密钥的 Windows 系统上。错误：{e}")
        return

    # 2. 读取明文数据
    with open(args.input, 'rb') as f:
        data = f.read()

    # 3. 准备 IV
    iv_bytes = bytes.fromhex(args.iv)
    if len(iv_bytes) != 16:
        raise ValueError("IV 必须为 16 字节（32位16进制）")

    print(f"✅ IV 是：{iv_bytes.hex()}")

    # 4. SM4 CBC 加密
    ciphertext = sm4_cbc_encrypt(data, sm4_key, iv_bytes)

    # 5. 写入密文
    with open(args.output, 'wb') as f:
        f.write(ciphertext)

    print(f"✅ 文件加密完成，输出文件：{args.output}")

if __name__ == "__main__":
    import win32crypt  # 需要安装 pywin32
    main()
