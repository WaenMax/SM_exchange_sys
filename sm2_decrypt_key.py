import argparse
from gmssl.sm2 import CryptSM2
import win32crypt  # 需要安装 pywin32


def decrypt_with_dpapi(encrypted_data: bytes) -> str:
    """
    使用 Windows DPAPI 解密数据
    """
    decrypted_data = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)
    return decrypted_data[1].decode('utf-8')


def main():
    parser = argparse.ArgumentParser(description="用DPAPI保护的SM2私钥解密SM4密钥")
    parser.add_argument('--sk_file', required=True, help="DPAPI加密的SM2私钥文件路径")
    parser.add_argument('--infile', required=True, help="SM2加密的SM4密钥文件路径")
    parser.add_argument('--out', required=True, help="输出解密后的SM4密钥文件路径")
    args = parser.parse_args()

    # 1. 读取并解密 SM2 私钥
    with open(args.sk_file, 'rb') as f:
        encrypted_private_key = f.read()
    private_key = decrypt_with_dpapi(encrypted_private_key)
    print("SM2私钥已通过 DPAPI 解密")

    # 2. 读取 SM2 加密的 SM4 密钥
    with open(args.infile, 'rb') as f:
        encrypted_sm4_key = f.read()

    # 3. 使用 SM2 私钥解密 SM4 密钥
    sm2_crypt = CryptSM2(public_key='', private_key=private_key)
    sm4_key = sm2_crypt.decrypt(encrypted_sm4_key)

    # 4. 自动创建输出目录
    output_dir = os.path.dirname(args.out)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 5. 写出解密后的 SM4 密钥
    with open(args.out, 'wb') as f:
        f.write(sm4_key)

    print(f"SM4密钥已成功解密并保存至：{args.out}")


if __name__ == "__main__":
    import os
    import win32crypt
    main()
