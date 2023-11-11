from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256


DATA = b"Hey friends, this is a longer message!!!"
KEY = b"yellow submarine"


def print_bytes(data: bytes):
    for i, b in enumerate(data):
        print(f"{b:02x}", end="")
        if (i+1) % 4 == 0:
            print("", end="")
    print()


def aes_ecb(data, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    print_bytes(ct_bytes)
    print("AES-ECB")


def aes_cbc(data, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    print_bytes(ct_bytes)
    print("AES-CBC")


def aes_ctr(data, key: bytes, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ct_bytes = cipher.encrypt(data)
    print_bytes(ct_bytes)
    print("AES-CTR")


def sha_256(data):
    h = SHA256.new()
    h.update(data)
    digest = h.digest()
    print_bytes(digest)


def main():
    aes_ecb(DATA, KEY)
    aes_cbc(DATA, KEY, bytes(16))
    aes_ctr(DATA, KEY, bytes(8))


if __name__ == "__main__":
    main()
