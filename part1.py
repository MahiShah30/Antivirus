import hashlib
#Get Hash of file
def md5_hash(filename):
    with open(filename,"rb") as f: # rb--> open file in binary mode
        bytes=f.read()
        md5Hash=hashlib.md5(bytes).hexdigest() # Convert file into hash 
    return md5Hash
#print(md5_hash("keylogger.zip"))

#Malware Detection By Hash
def malware_checker(pathOfFile):
    hash_malware_check=md5_hash(pathOfFile)
    counter=0 
    
    malware_hashes= list(open("virusHash.txt","r").read().split('\n'))
    virusInfo= list(open("VirusInfo.txt","r").read().split('\n'))

    for i in malware_hashes:
        if i == hash_malware_check:
            return virusInfo[counter]
        counter += 1
    return 0

            
        
print(malware_checker("keylogger.zip"))



