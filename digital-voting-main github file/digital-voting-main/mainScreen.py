import mysql.connector
import pandas as pd
import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode,b64decode

def mainScreen(FirstName,username):
    print(f'Welcome {FirstName}!')
    candidateList = pd.DataFrame(getCandidates(),columns=['id','FirstName','LastName','Position'])
    positionList = getPosition()
    voteList = []
    for position in positionList:
        print("Voting for",position[0])
        subList = candidateList.loc[candidateList['Position']==position[0]]
        idList = subList['id'].values
        idList = np.append(idList,0)
        for idx in range(0,subList['id'].size):
            print(subList['id'].values[idx],": ",subList['FirstName'].values[idx],subList['LastName'].values[idx])
        print("0 : ABSTAIN")
        userVote = -1
        while(userVote == -1):
            try:
                userVote = int(input("Input ID of Vote: "))
            except ValueError:
                userVote = -1
            if(not userVote in idList):
                print("Invalid Input Try again.")
                userVote = -1
        print("Vote Counted")
        if userVote != 0:
            voteList = np.append(voteList,userVote)
        print("_________________________________________________")
    print("Thanks for Voting!")
    message = encryptVotes(username,voteList)
    encryptFinal(message)


def getCandidates():
    mydb=mysql.connector.connect(
        host = 'ss3010.rutgers-sci.domains',
        user = 'ssrutge4_user1',
        password = 'qwer1234qwer',
        database = 'ssrutge4_ECE424'
    )
    cursor = mydb.cursor()
    queryString = "select id,first_name,last_name,position from Candidate"
    cursor.execute(queryString)
    result = cursor.fetchall()
    mydb.close()
    cursor.close()
    return result

def getPosition():
    mydb=mysql.connector.connect(
        host = 'ss3010.rutgers-sci.domains',
        user = 'ssrutge4_user1',
        password = 'qwer1234qwer',
        database = 'ssrutge4_ECE424'
    )
    cursor = mydb.cursor()
    queryString = "select distinct(position) from Candidate"
    cursor.execute(queryString)
    result = cursor.fetchall()
    mydb.close()
    cursor.close()
    return result

def encryptVotes(userID,votes):
    new_key = RSA.importKey(open('counter_public_key.pem').read())
    voteString = []
    for vote in votes:
        preVote = str(vote)
        voteString = np.append(voteString,preVote)
    joinedVotes = ',,,,,'.join(voteString)
    counter_cipher = PKCS1_OAEP.new(new_key)
    cipherVote = counter_cipher.encrypt(joinedVotes.encode("utf-8"))
    preID = userID + ",,,,,"
    ID = preID.encode("utf-8")
    message = ID + cipherVote
    return message


def encryptFinal(votes):
    authenticator_public_key = RSA.importKey(open('auth_public_key.pem').read())
    counter_cipher = PKCS1_OAEP.new(authenticator_public_key)
    # encrypted_ballot = counter_cipher.encrypt(votes)
    chunk_length = 64
    chunks = [votes[i:i+chunk_length] for i in range(0, len(votes), chunk_length)]
    encrypted_ballot = b''
    for chunk in chunks:
        encrypted_ballot = encrypted_ballot + counter_cipher.encrypt(chunk)
    with open("auth_ballot.ballot", "wb") as f:
        f.write(encrypted_ballot)