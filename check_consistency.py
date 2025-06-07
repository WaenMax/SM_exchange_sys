import argparse
from gmssl import sm3

def sm3_hash_file(filename):
    with open(filename, 'rb') as f:
        data = bytearray(f.read())  # ✅ 改成 bytearray
    return sm3.sm3_hash(data)

def main():
    parser = argparse.ArgumentParser(description="检查两个文件是否一致（使用SM3哈希）")
    parser.add_argument('--file1', required=True, help="第一个文件路径")
    parser.add_argument('--file2', required=True, help="第二个文件路径")
    args = parser.parse_args()

    hash1 = sm3_hash_file(args.file1)
    hash2 = sm3_hash_file(args.file2)

    print(f"File1 SM3 Hash: {hash1}")
    print(f"File2 SM3 Hash: {hash2}")

    if hash1 == hash2:
        print("success")
    else:
        print("failure")

if __name__ == "__main__":
    main()
