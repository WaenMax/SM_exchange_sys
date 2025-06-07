import os
import argparse
import win32crypt  # 需要 pywin32 库

def protect_key_with_dpapi(key_bytes: bytes) -> bytes:
    # 使用 Windows DPAPI 加密
    return win32crypt.CryptProtectData(key_bytes, None, None, None, None, 0)

def main():
    parser = argparse.ArgumentParser(description="生成随机SM4密钥并使用Windows DPAPI加密保存")
    parser.add_argument('--out', required=True, help="输出加密密钥文件名")
    args = parser.parse_args()

    sm4_key = os.urandom(16)  # SM4密钥16字节随机
    print(f"SM4随机密钥：{sm4_key.hex()}\n")

    encrypted_key = protect_key_with_dpapi(sm4_key)

    with open(args.out, 'wb') as f:
        f.write(encrypted_key)

    print(f"SM4随机密钥生成并已使用Windows DPAPI加密保存至 {args.out}")

if __name__ == "__main__":
    main()
