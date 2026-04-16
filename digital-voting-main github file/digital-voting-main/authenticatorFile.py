from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from base64 import b64encode,b64decode
import mysql.connector

class Authenticator:

    def __init__(self):
        #self.auth_key = RSA.generate(4096,e=65537)
        self.auth_private_key = RSA.importKey(open('auth_private_key.pem').read())
        self.auth_public_key = RSA.importKey(open('auth_public_key.pem').read())

    def getKey(self):
        print("")
    def sendKey(self):
        print()
    def authenticate(self):
        with open("auth_ballot.ballot", "rb") as f:
            messages = f.read()
        encryptedVoteList = ""
        deliminator = ",,,,,".encode("utf-8")
        auth_cipher = PKCS1_OAEP.new(self.auth_private_key)

        # plainMessage = auth_cipher.decrypt(messages)
        chunk_length = 64
        chunks = [messages[i:i+chunk_length] for i in range(0, len(messages), chunk_length)]
        plainMessage = ""
        for chunk in chunks:
            plainMessage = plainMessage + auth_cipher.decrypt(chunk)
            
        [id_byte, cipherVote_2] = plainMessage.split(b',,,,,')
        userID = id_byte.decode("utf-8")
        mydb = mysql.connector.connect(
            host='ss3010.rutgers-sci.domains',
            user='ssrutge4_user1',
            password="qwer1234qwer",
            database='ssrutge4_ECE424'
        )
        dbCursor = mydb.cursor()
        queryString = "select has_registered from Employees where id = " + userID
        dbCursor.execute(queryString)
        result = dbCursor.fetchone()
        if result[0] == "True":
            dbCursor.close()
            mydb.close()
            raise Exception("User Already Voted")
        else:
            # pass cipherVote_2 to Counter
            queryString = "update Employees set has_registered = True where id = " + userID
            dbCursor.execute(queryString)
            dbCursor.close()
            mydb.close()
            # signature = b64encode(RSA.sign(cipherVote_2,self.auth_private_key),"SHA-512")
            # auth_cipher = PKCS1_OAEP.new(getKey())
            # cipherVote_3 = auth_cipher.encrypt(cipherVote_2)
            # return [cipherVote_3,signature]
        create_Signature(cipherVote_2)
        create_Encrypted_Ballot(cipherVote_2)

def create_Signature(vote):
    # Sign the ballot using authenticator's private key
    auth_private_key = RSA.importKey(open('auth_private_key.pem').read())
    ballot = vote.encode("utf-8")
    hash1 = SHA256.new(ballot)
    signer = PKCS115_SigScheme(auth_private_key)
    signature = signer.sign(hash1)
    with open("signature.txt", "wb") as f:
        f.write(signature)


def create_Encrypted_Ballot(vote):
    # Encrypt ballot using COUNTER's PUBLIC KEY
    ballot = vote.encode("utf-8")
    counter_public_key = RSA.importKey(open('counter_public_key.pem').read())
    counter_cipher = PKCS1_OAEP.new(counter_public_key)
    encrypted_ballot = counter_cipher.encrypt(ballot)
    with open("enc_ballot.ballot", "wb") as f:
        f.write(encrypted_ballot)

def mainTest():
    new_key = RSA.generate(1024,e=65537)
    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")
    auth_cipher = PKCS1_OAEP.new(new_key)
    cipherVote = auth_cipher.encrypt("vote".encode("utf-8"))
    ID = "123123,,,,,".encode("utf-8")
    message = ID + cipherVote
    [id_byte,cipherVote_2] = message.split(b',,,,,')
    print(id_byte.decode("utf-8"),"\n")
    auth_cipher = PKCS1_OAEP.new(new_key)
    plainVote = auth_cipher.decrypt(cipherVote_2)
    print(plainVote.decode("utf-8"), "\n")