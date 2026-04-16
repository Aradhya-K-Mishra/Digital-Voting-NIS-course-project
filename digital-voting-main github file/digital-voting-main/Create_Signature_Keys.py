# -*- coding: utf-8 -*-
import os
import binascii
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def create_Keys():
                ########### AUTHENTICATOR KEYS ##########
    #Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=65537)
    #The private key in PEM format
    auth_private_key = new_key.exportKey("PEM")
    #The public key in PEM Format
    auth_public_key = new_key.publickey().exportKey("PEM")
   
    #Write private key into file
    fd = open("auth_private_key.pem", "wb")
    fd.write(auth_private_key)
    fd.close()
   
    #Write public key into file
    fd = open("auth_public_key.pem", "wb")
    fd.write(auth_public_key)
    fd.close()
                ########### COUNTER KEYS ##########
    #Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=65537)
    #The private key in PEM format
    counter_private_key = new_key.exportKey("PEM")
    #The public key in PEM Format
    counter_public_key = new_key.publickey().exportKey("PEM")
   
    #Write private key into file
    fd = open("counter_private_key.pem", "wb")
    fd.write(counter_private_key )
    fd.close()
   
    #Write public key into file
    fd = open("counter_public_key.pem", "wb")
    fd.write(counter_public_key)
    fd.close()
    
    
    
def create_Signature():
   
    #Sign the ballot using authenticator's private key
    auth_private_key = RSA.importKey(open('auth_private_key.pem').read())
    ballot = b'This is Ballot'
    hash = SHA256.new(ballot)
    signer = PKCS115_SigScheme(auth_private_key)
    signature = signer.sign(hash)
    with open("signature.txt", "wb") as f:
        f.write(signature)

def create_Encrypted_Ballot():
    
    #Encrypt ballot using COUNTER's PUBLIC KEY
    ballot = b'This is Ballot'
    counter_public_key = RSA.importKey(open('counter_public_key.pem').read())
    counter_cipher = PKCS1_OAEP.new(counter_public_key)
    encrypted_ballot  = counter_cipher.encrypt(ballot)
    with open("enc_ballot.ballot", "wb") as f:
        f.write(encrypted_ballot) 
        
        
#Main body

create_Keys()
create_Encrypted_Ballot()
create_Signature()



