from fame.core.module import ProcessingModule
import hashlib

class file_hash(ProcessingModule):
    name = 'filehash'
    description = 'calculate the hash value of the file'
    def each(self, target):
        output = open('hash_value.txt','w')
        ###########################################################################################
        file = target # Location of the file (can be set a different way)
        BLOCK_SIZE = 65536 # The size of each read from the file

        file_hash_sha256 = hashlib.sha256() # Create the hash object, can use something other than `.sha256()` if you wish
        with open(file, 'rb') as f: # Open the file to read it's bytes
            fb = f.read(BLOCK_SIZE) # Read from the file. Take in the amount declared above
            while len(fb) > 0: # While there is still data being read from the file
                file_hash_sha256.update(fb) # Update the hash
                fb = f.read(BLOCK_SIZE) # Read the next block from the file

        print ('sha256 : ' , file_hash_sha256.hexdigest(), file = output) # Get the hexadecimal digest of the hash
        ###########################################################################################
        file = target # Location of the file (can be set a different way)
        BLOCK_SIZE = 65536 # The size of each read from the file

        file_hash_sha1 = hashlib.sha1() # Create the hash object, can use something other than `.sha256()` if you wish
        with open(file, 'rb') as f: # Open the file to read it's bytes
            fb = f.read(BLOCK_SIZE) # Read from the file. Take in the amount declared above
            while len(fb) > 0: # While there is still data being read from the file
                file_hash_sha1.update(fb) # Update the hash
                fb = f.read(BLOCK_SIZE) # Read the next block from the file

        print('sha1 : ' , file_hash_sha1.hexdigest(), file = output) # Get the hexadecimal digest of the hash
        ###########################################################################################
        file = target # Location of the file (can be set a different way)
        BLOCK_SIZE = 65536 # The size of each read from the file

        file_hash_md5 = hashlib.md5() # Create the hash object, can use something other than `.sha256()` if you wish
        with open(file, 'rb') as f: # Open the file to read it's bytes
            fb = f.read(BLOCK_SIZE) # Read from the file. Take in the amount declared above
            while len(fb) > 0: # While there is still data being read from the file
                file_hash_md5.update(fb) # Update the hash
                fb = f.read(BLOCK_SIZE) # Read the next block from the file

        print('md5 : ',file_hash_md5.hexdigest(), file = output) # Get the hexadecimal digest of the hash        
        self.add_support_file('Hash Value',output)
        output.close()
        return True