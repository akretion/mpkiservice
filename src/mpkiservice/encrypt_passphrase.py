#! /bin/python3

# https://stackoverflow.com/questions/11132714/python-two-way-alphanumeric-encryption

from Crypto.Cipher import AES
from Crypto import Random


#key = "TESTTESTTESTTEST".encode("utf8")  # To put in .htpasswd
print("Enter the decrypt key of the file: (save it in the .htpasswd)")
key = input().encode("utf8")
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CFB, iv)
#msg = iv + cipher.encrypt("test".encode("utf8"))  # The openssl passphrase
print("Enter the OpenSSL passphrase to encrypt:")
msg = iv + cipher.encrypt(input().encode("utf8"))  # The openssl passphrase
print("Here is the encrypted passphrase to put in the .env file: " + msg.hex())
