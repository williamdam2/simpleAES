import base64
import hashlib
import pyaes
import random

class SimpleAES:
    def __init__(self):
        self.salt = b'This is Salt'
        self.iterationCount = 1000
        # Create random 16 bytes IV # a fake random 
        random.seed(41098) # set the seed to 1234
        self.iv = bytes(random.getrandbits(8) for _ in range(16)) # generate 16 random bytes

    def genKey(self,password:str):
        # Create 32 bytes key
        password = bytes(password,encoding='utf-8')
        return hashlib.pbkdf2_hmac('sha256', password, self.salt, self.iterationCount)
    
    def encrypt(self,key:bytes,text:str):
    # Encryption with AES-256-CBC , return a base64 string
        encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, self.iv))
        cipherText = encrypter.feed(text.encode('utf8'))
        cipherText += encrypter.feed()
        # encode to base64 string 
        cipherText = base64.b64encode(cipherText).decode('utf-8')
        return cipherText
    
    def decrypt(self,key:bytes,encryptedText:str):
        # Decryption with AES-256-CBC
        # decode first
        encryptedText = base64.b64decode(encryptedText)
        decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, self.iv))
        decryptedData = decrypter.feed(encryptedText)
        decryptedData += decrypter.feed()
        decryptedData = str(decryptedData,encoding="utf-8")
        return decryptedData

password = "04010098"
cipher = SimpleAES()
key = cipher.genKey(password)
message = "Hello this is Wade, I need to send this message out"
encryptedText = cipher.encrypt(key,message)
decryptedText = cipher.decrypt(key,encryptedText)

print("encryptedText: ",encryptedText)
print("decryptedText: ",decryptedText)

