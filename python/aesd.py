import base64
import hashlib
import hmac
import sys
from Crypto.Cipher import AES


if( len(sys.argv) != 3 ):
    print("Usage: python aesd.py <password> <base64 file>")
    print("Example: python aesd.py secret smsx-1234.txt")
    print("File format: base64(<32 bytes HMAC hash><16 bytes IV><aes-256-CBC-PKCS#5(data)>")
else:
    with open( sys.argv[2], 'rb') as dataFile:
            data=dataFile.read()

    binData = base64.b64decode(data)
    HMAC = binData[0:32]
    IV = binData[32:48]
    ENC = binData[48:]

    password = sys.argv[1]
    salt = 'SMSX'
    key = hashlib.sha256(password + salt).digest()
    authkey = hashlib.sha256(key).digest()

    dig = hmac.new(authkey, IV+ENC, hashlib.sha256).digest()
    if( not hmac.compare_digest( dig, HMAC ) ):
        print("Integrity failure")
        exit(1)

    AESobj = AES.new(key , AES.MODE_CBC, IV)
    plain  = AESobj.decrypt(ENC)

    # PKCS5Padding
    paddingSize = ord(plain[-1])

    print(plain[:-paddingSize])
