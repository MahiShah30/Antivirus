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
    malware_hashes=open("virushash.txt","r")
    malware_hashes_read=malware_hashes.read()
    malware_hashes.close()
    
    virusInfo=open("VirusInfo.txt","r").read()
    if malware_hashes_read.find(hash_malware_check) !=-1:
        return virusInfo[malware_hashes_read.index(hash_malware_check)]
    else:
            return "green"
print(malware_checker("keylogger.zip"))



