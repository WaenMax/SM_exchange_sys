import argparse
import hashlib
from gmssl.sm2 import CryptSM2

def main():
    parser = argparse.ArgumentParser(description="SM2签名验证")
    parser.add_argument('--pk_file', required=True, help="对方SM2公钥文件")
    parser.add_argument('--infile', required=True, help="需要验证的文件")
    parser.add_argument('--sig_file', required=True, help="签名文件")
    args = parser.parse_args()

    with open(args.pk_file, 'r') as f:
        public_key = f.read().strip()
    with open(args.infile, 'rb') as f:
        data = f.read()
    with open(args.sig_file, 'r') as f:
        signature = f.read().strip()

    data_hash = hashlib.sha256(data).hexdigest()

    sm2_crypt = CryptSM2(public_key=public_key, private_key='')
    verified = sm2_crypt.verify(signature, data_hash.encode())

    print(f"签名验证结果: {'有效' if verified else '无效'}")

if __name__ == "__main__":
    main()
