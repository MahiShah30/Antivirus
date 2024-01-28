import hashlib
import os 

#Global Variable
malware_hashes= list(open("virusHash.txt","r").read().split('\n'))
virusInfo= list(open("VirusInfo.txt","r").read().split('\n'))

#Get Hash of file
def sha256_hash(filename):
    with open(filename,"rb") as f: # rb--> open file in binary mode
        bytes=f.read()
        sha256hash=hashlib.sha256(bytes).hexdigest() # Convert file into hash 
        
        f.close()
        #print(sha256hash)
    return sha256hash

#Malware Detection By Hash
def malware_checker_one(pathOfFile):
    global malware_hashes
    global virusInfo
    
    hash_malware_check=sha256_hash(pathOfFile)
    counter=0

    for i in malware_hashes:
        if i == hash_malware_check:
            return virusInfo[counter]
        counter += 1
        
    return 0

#Malware Detection in folder 

        #List of files
print(malware_checker_one("keylogger.zip"))



