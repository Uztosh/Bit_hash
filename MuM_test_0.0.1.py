import hashlib
import base58
import base64
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import number_to_string
import signal
import sys

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def private_key_to_wif(private_key, compressed=True):
    prefix = b'\x80'
    if compressed:
        private_key += b'\x01'
    extended_key = prefix + private_key
    checksum = sha256(sha256(extended_key))[:4]
    return base58.b58encode(extended_key + checksum).decode()

def public_key_to_p2pkh(public_key):
    sha256_result = sha256(public_key)
    ripemd160_result = ripemd160(sha256_result)
    prefix = b'\x00'
    hashed_public_key = prefix + ripemd160_result
    checksum = sha256(sha256(hashed_public_key))[:4]
    return base58.b58encode(hashed_public_key + checksum).decode()

def public_key_to_bech32(public_key):
    return "Bech32_Encoding_Not_Implemented"

def base58check_encode(data):
    checksum = sha256(sha256(data))[:4]
    return base58.b58encode(data + checksum).decode()

def create_private_key_range(start, end, progress_callback=None, target_p2pkh=None):
    private_keys = []
    for i in range(start, end + 1):
        private_key_int = i
        private_key = number_to_string(private_key_int, SECP256k1.order)
        wif_compressed = private_key_to_wif(private_key, compressed=True)
        wif_uncompressed = private_key_to_wif(private_key, compressed=False)

        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        vk = sk.verifying_key
        public_key_compressed = b'\x02' + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]
        public_key_uncompressed = b'\x04' + vk.to_string()

        p2pkh_address = public_key_to_p2pkh(public_key_compressed)
        bech32_address = public_key_to_bech32(public_key_compressed)

        public_key_hash = ripemd160(sha256(public_key_compressed))
        public_key_hash_reversed = public_key_hash[::-1]

        private_key_base64 = base64.b64encode(private_key).decode()
        public_key_hash_base64 = base64.b64encode(public_key_hash).decode()

        private_key_bin = bin(int.from_bytes(private_key, 'big'))[2:]
        public_key_hash_bin = bin(int.from_bytes(public_key_hash, 'big'))[2:]

        base58check_result = base58check_encode(public_key_compressed)

        if target_p2pkh and p2pkh_address == target_p2pkh:
            return {
                'private_key_int': private_key_int,
                'private_key_length': len(hex(private_key_int)) - 2,
                'wif_compressed': wif_compressed,
                'wif_uncompressed': wif_uncompressed,
                'p2pkh_address': p2pkh_address,
                'bech32_address': bech32_address,
                'public_key_compressed': public_key_compressed.hex(),
                'public_key_uncompressed': public_key_uncompressed.hex(),
                'public_key_hash_reversed': public_key_hash_reversed.hex(),
                'private_key_base64': private_key_base64,
                'public_key_hash_base64': public_key_hash_base64,
                'private_key_bin': private_key_bin,
                'public_key_hash_bin': public_key_hash_bin,
                'base58check_result': base58check_result,
                'x': vk.pubkey.point.x(),
                'y': vk.pubkey.point.y()
            }

        if progress_callback and i % 100 == 0:
            progress_callback(i)

    return None

def save_private_keys_to_file(start, end, filename="private_keys2.txt", target_p2pkh=None):
    start_range = int(start, 16)
    end_range = int(end, 16)

    print(f"Private kalitlarni {start_range} dan {end_range} gacha yaratish...")
    result = create_private_key_range(start_range, end_range, progress_callback=report_progress, target_p2pkh=target_p2pkh)

    if result:
        print(f"Mos keluvchi P2PKH manzili topildi: {result['p2pkh_address']}")
        with open(filename, "w") as f:
            f.write(f"Private Key (Int): {result['private_key_int']}\n")
            f.write(f"Private Key Length: {result['private_key_length']} bayt\n")
            f.write(f"WIF (Compressed): {result['wif_compressed']}\n")
            f.write(f"WIF (Uncompressed): {result['wif_uncompressed']}\n")
            f.write(f"P2PKH Address: {result['p2pkh_address']}\n")
            f.write(f"Bech32 Address: {result['bech32_address']}\n")
            f.write(f"Public Key (Compressed): {result['public_key_compressed']}\n")
            f.write(f"Public Key (Uncompressed): {result['public_key_uncompressed']}\n")
            f.write(f"Public Key Hash (Reversed): {result['public_key_hash_reversed']}\n")
            f.write(f"Private Key Base64: {result['private_key_base64']}\n")
            f.write(f"Public Key Hash Base64: {result['public_key_hash_base64']}\n")
            f.write(f"Private Key Binary: {result['private_key_bin']}\n")
            f.write(f"Public Key Hash Binary: {result['public_key_hash_bin']}\n")
            f.write(f"Base58Check Result: {result['base58check_result']}\n")
            f.write(f"Elliptic Curve Points - X: {result['x']}, Y: {result['y']}\n")
            f.write("\n")
        print(f"Ma'lumotlar {filename} faylga muvaffaqiyatli saqlandi.")
    else:
        print("Kiritilgan diapazonda mos P2PKH manzili topilmadi.")

def report_progress(i):
    print(f"Yaratilgan kalitlar soni: {i} ta...")

def handle_interrupt(signal, frame):
    print("\nJarayon to'xtatildi.")
    sys.exit(0)

# Signalni sozlash (Ctrl+C ni ushlash uchun)
signal.signal(signal.SIGINT, handle_interrupt)

# Misol uchun foydalanish
def main():
    predefined_inputs = {
        "start_range": "0000000000000000000000000000000000000000000000040000000000000000",
        "end_range": "000000000000000000000000000000000000000000000007ffffffffffffffff",
        "target_p2pkh": "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9"
    }

    start_range = predefined_inputs["start_range"]
    end_range = predefined_inputs["end_range"]
    target_p2pkh = predefined_inputs["target_p2pkh"]

    save_private_keys_to_file(start_range, end_range, target_p2pkh=target_p2pkh)

if __name__ == "__main__":
    main()
