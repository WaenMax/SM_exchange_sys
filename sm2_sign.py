import argparse
import hashlib
from gmssl.sm2 import CryptSM2
import win32crypt


def decrypt_with_dpapi(encrypted_data: bytes) -> str:
    """
    使用 Windows DPAPI 解密数据
    """
    decrypted_data = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)
    return decrypted_data[1].decode('utf-8')


def main():
    parser = argparse.ArgumentParser(description="使用DPAPI保护的SM2私钥进行数字签名")
    parser.add_argument('--sk_file', required=True, help="DPAPI加密的SM2私钥文件路径")
    parser.add_argument('--infile', required=True, help="需要签名的文件路径")
    parser.add_argument('--out', required=True, help="输出签名文件路径")
    args = parser.parse_args()

    # 1. 读取并解密私钥
    with open(args.sk_file, 'rb') as f:
        encrypted_private_key = f.read()
    private_key = decrypt_with_dpapi(encrypted_private_key)
    print("私钥已通过 DPAPI 解密")

    # 2. 读取待签名文件
    with open(args.infile, 'rb') as f:
        data = f.read()
    data_hash = hashlib.sha256(data).hexdigest()
    print(f"数据Hash: {data_hash}")

    # 3. 初始化 SM2 并签名
    sm2_crypt = CryptSM2(private_key=private_key, public_key='')

    # 签名（user_id 可选）
    signature = sm2_crypt.sign(data_hash.encode(), b'12345678')

    # 4. 保存签名
    with open(args.out, 'w') as f:
        f.write(signature)

    print(f"签名完成，输出文件：{args.out}")


if __name__ == "__main__":
    main()
