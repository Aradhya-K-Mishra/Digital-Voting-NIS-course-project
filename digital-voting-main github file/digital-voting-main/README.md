#VOTE COUNTER

1. Run the Create_Signature_Keys.py
      What this does is it creates test signature, encrypted ballot, and public/private keys for Authenticator and Vote Counter. 
  
2. Run the Votecounter.py 

Here is what is happening in the vote counter module.
   1. Receives "Encrypted Ballot", "Signature", and "Authenticator's public key"
   2. Decrypts the encrypted ballot with its own(Vote counter) private key to get plain ballot.
   3. Calculates the hash of the plain ballot.
   4. Verifies/Authenticates the signed ballot by using Authenticator's public key. The way it works is, Authenticator's public key is used on the signature to get the Hashed function of the signed ballot. Also, in step 3, we calculate the hash function of the plain ballot. By comparing these two, we can verify the authenticity of the sender(Authenticator).
   
