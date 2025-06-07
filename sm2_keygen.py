import argparse
from gmssl.sm2 import CryptSM2
import os
import win32crypt  # 需要安装 pywin32


def protect_with_dpapi(plaintext: bytes) -> bytes:
    """
    使用 Windows DPAPI 加密数据
    """
    return win32crypt.CryptProtectData(plaintext, None, None, None, None, 0)


def main():
    parser = argparse.ArgumentParser(description="生成SM2密钥对并使用Windows DPAPI加密保护私钥")
    parser.add_argument('--sk_out', required=True, help="输出加密私钥文件路径")
    parser.add_argument('--pk_out', required=True, help="输出公钥文件路径")
    args = parser.parse_args()

    # 1. 生成随机私钥（256位 / 32字节）
    private_key_hex = os.urandom(32).hex()
    print(f"SM2私钥（明文 hex）: {private_key_hex}")

    # 2. 初始化 SM2 对象并生成公钥
    sm2_crypt = CryptSM2(private_key=private_key_hex, public_key='')

    public_key = sm2_crypt._kg(int(private_key_hex, 16), sm2_crypt.ecc_table['g'])
    print(f"SM2公钥（hex）: {public_key}")

    # 3. 使用 DPAPI 加密私钥
    encrypted_private_key = protect_with_dpapi(private_key_hex.encode('utf-8'))

    # 4. 写入加密私钥到文件
    with open(args.sk_out, 'wb') as f:
        f.write(encrypted_private_key)
    print(f"私钥已使用 DPAPI 加密并保存至: {args.sk_out}")

    # 5. 写入公钥到文件
    with open(args.pk_out, 'w') as f:
        f.write(public_key)
    print(f"公钥已保存至: {args.pk_out}")

    print("SM2密钥对生成完成")


if __name__ == "__main__":
    main()
