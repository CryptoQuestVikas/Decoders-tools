import base64, codecs, hashlib, string, re, zipfile, threading, rarfile, jwt
from itertools import cycle
import PyPDF2
from stegano import lsb

# ------------------ Auto Detection ------------------
def detect_encoding(data):
    hints = []
    if re.fullmatch(r"[A-Za-z0-9+/=]+", data) and len(data) % 4 == 0:
        hints.append("Base64")
    if re.fullmatch(r"[0-9a-fA-F]+", data) and len(data) % 2 == 0:
        hints.append("Hex")
    if data.isalpha():
        hints.append("ROT13 / Caesar")
    return hints or ["No obvious encoding detected"]

# ------------------ Decoders ------------------
def decode_base64(data):
    try:
        return base64.b64decode(data).decode('utf-8')
    except Exception: return "[Base64] Invalid input."

def decode_hex(data):
    try:
        return bytes.fromhex(data).decode('utf-8')
    except Exception: return "[Hex] Invalid input."

def decode_rot13(data):
    return codecs.decode(data, 'rot_13')

def decode_xor(data, key):
    try:
        return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, cycle(key)))
    except Exception: return "[XOR] Decode failed."

# ------------------ Caesar & Vigenère Crack ------------------
def crack_caesar(data):
    results = []
    for shift in range(1, 26):
        decoded = ''.join(
            chr((ord(c) - (65 if c.isupper() else 97) - shift) % 26 + (65 if c.isupper() else 97)) if c.isalpha() else c
            for c in data
        )
        results.append(f"Shift {shift:2}: {decoded}")
    return results

def crack_vigenere(ciphertext, keywords):
    results = []
    for key in keywords:
        decrypted = ''
        key_cycle = cycle(key.lower())
        for char in ciphertext:
            if char.isalpha():
                shift = ord(next(key_cycle)) - 97
                base = ord('A') if char.isupper() else ord('a')
                decrypted += chr((ord(char) - base - shift) % 26 + base)
            else:
                decrypted += char
        results.append((key, decrypted))
    return results

# ------------------ Hash Cracker ------------------
def identify_hash(hash_val):
    hlen = len(hash_val)
    if hlen == 32:
        return "MD5"
    elif hlen == 40:
        return "SHA1"
    elif hlen == 64:
        return "SHA256"
    return "Unknown"

def threaded_hash_crack(hash_val, wordlist_path, hash_type):
    found = [None]
    def crack_chunk(words):
        for word in words:
            if found[0]: break
            h = hashlib.new(hash_type.lower())
            h.update(word.encode())
            if h.hexdigest() == hash_val:
                found[0] = word
                break
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f.readlines()]
            chunk_size = len(words) // 8 or 1
            threads = []
            for i in range(0, len(words), chunk_size):
                chunk = words[i:i + chunk_size]
                t = threading.Thread(target=crack_chunk, args=(chunk,))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
        return f"[+] Match: {found[0]}" if found[0] else "[!] Not found."
    except Exception as e:
        return f"[!] Error: {e}"

# ------------------ File Crackers ------------------
def crack_pdf_password(pdf_path, wordlist_path):
    try:
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            if not reader.is_encrypted:
                return "[+] PDF is not encrypted."
            with open(wordlist_path, 'r', encoding='utf-8') as wl:
                for line in wl:
                    password = line.strip()
                    try:
                        if reader.decrypt(password):
                            return f"[+] Password found: {password}"
                    except:
                        continue
        return "[!] Password not found."
    except Exception as e:
        return f"[!] Error: {e}"

def crack_zip_password(zip_path, wordlist_path):
    try:
        with zipfile.ZipFile(zip_path) as zf:
            with open(wordlist_path, 'r', encoding='utf-8') as wl:
                for line in wl:
                    password = line.strip().encode('utf-8')
                    try:
                        zf.extractall(pwd=password)
                        return f"[+] Password found: {password.decode()}"
                    except:
                        continue
        return "[!] Password not found."
    except Exception as e:
        return f"[!] Error: {e}"

def crack_rar_password(rar_path, wordlist_path):
    try:
        with rarfile.RarFile(rar_path) as rf:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    pwd = line.strip()
                    try:
                        rf.extractall(pwd=pwd.encode('utf-8'))
                        return f"[+] Password found: {pwd}"
                    except:
                        continue
        return "[!] Password not found."
    except Exception as e:
        return f"[!] Error: {e}"

# ------------------ JWT Decoder ------------------
def decode_jwt_token(token):
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return f"Header: {header}\nPayload: {payload}"
    except Exception as e:
        return f"[!] JWT decode error: {e}"

# ------------------ Steganography ------------------
def extract_steganography(image_path):
    try:
        secret = lsb.reveal(image_path)
        return f"[+] Hidden message: {secret}" if secret else "[!] No hidden data found."
    except Exception as e:
        return f"[!] Error reading image: {e}"

# ------------------ Main CLI ------------------
def main():
    print("\n--------------------Decoder & Cracker Tool--------------------")
    print("\n🔐 Made By Vikas Lahare | GitHub: https://github.com/CryptoQuestVikas")
    print("1. Detect encoding")
    print("2. Decode Base64 / Hex / ROT13")
    print("3. Crack Caesar Cipher")
    print("4. Crack Vigenère Cipher (with wordlist)")
    print("5. XOR Decrypt")
    print("6. Multi-threaded Hash Cracker")
    print("7. Crack PDF Password")
    print("8. Crack ZIP Password")
    print("9. Crack RAR Password")
    print("10.Decode JWT Token")
    print("11.Extract Image Steganography")
    print("0. Exit")

    while True:
        choice = input("\nChoice: ")

        if choice == '1':
            data = input("Enter encoded string: ")
            print("🔍 Possible Encodings:", detect_encoding(data))

        elif choice == '2':
            data = input("Input string: ")
            print("[Base64]:", decode_base64(data))
            print("[Hex]   :", decode_hex(data))
            print("[ROT13] :", decode_rot13(data))

        elif choice == '3':
            data = input("Enter Caesar cipher text: ")
            for line in crack_caesar(data):
                print(line)

        elif choice == '4':
            cipher = input("Enter Vigenère cipher text: ")
            path = input("Enter wordlist file: ")
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    words = [line.strip() for line in f.readlines()]
                    for key, text in crack_vigenere(cipher, words[:20]):
                        print(f"Key '{key}': {text}")
            except FileNotFoundError:
                print("[!] Wordlist not found.")

        elif choice == '5':
            data = input("Enter XOR-encoded string: ")
            key = input("Enter key: ")
            print("[XOR Decoded]:", decode_xor(data, key))

        elif choice == '6':
            hval = input("Enter hash value: ")
            algo = identify_hash(hval)
            wordlist = input("Enter wordlist path: ")
            print(threaded_hash_crack(hval, wordlist, algo))

        elif choice == '7':
            pdf = input("Enter PDF file path: ")
            wordlist = input("Enter wordlist path: ")
            print(crack_pdf_password(pdf, wordlist))

        elif choice == '8':
            zipf = input("Enter ZIP file path: ")
            wordlist = input("Enter wordlist path: ")
            print(crack_zip_password(zipf, wordlist))

        elif choice == '9':
            rar = input("Enter RAR file path: ")
            wordlist = input("Enter wordlist path: ")
            print(crack_rar_password(rar, wordlist))

        elif choice == '10':
            token = input("Enter JWT token: ")
            print(decode_jwt_token(token))

        elif choice == '11':
            img = input("Enter image file path: ")
            print(extract_steganography(img))

        elif choice == '0':
            print("Exiting.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
