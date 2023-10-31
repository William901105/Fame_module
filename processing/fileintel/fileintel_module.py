from fame.core.module import ProcessingModule
import zipfile
import csv
import sys
import subprocess
# Required for paths
import os
class NSRL(object):
    """
    Class to hold NSRL items.
    """
    def __init__(self, NSRLPath):
        self.NSRLPath = NSRLPath

    def add_headers(self, inputheaders):
        """
        Adds appropriate headers to input list.
        """
        inputheaders.append('NSRL SHA-1 or MD5 Match')

    def add_row(self, NSRLHashes, filehash, inputrow):
        """
        Adds the pulled data to the input row.
        """
        NSRLMatch = False
        if filehash.upper() in [n.upper() for n in NSRLHashes]:
            NSRLMatch = True

        inputrow.append(NSRLMatch)

    def lookup(self, filehashes, SevenZipPath=None):
        """
        Lookup the list of file hashes and returns a list of the
        hashes that exist in the NSRL.

        Inspired by: https://blog.didierstevens.com/2015/09/01/nsrl-py-using-
                      the-reference-data-set-of-the-national-software-
                      reference-library/

        """
        upperhashes = [f.upper() for f in filehashes]
        outputhashes = []

        if SevenZipPath is None:
            try:
                ZipFile = zipfile.ZipFile(self.NSRLPath)
            except:
                sys.stderr.write("ERROR: Problem with the NSRL file!  " +
                                 "Check the conf file?  " +
                                 "Check if the file is corrupt?\n")
                exit(1)

            fIn = ZipFile.open('NSRLFile.txt', 'r')
            csvIn = csv.reader(fIn, delimiter=',', skipinitialspace=True)

            outputhashes = self.searchhashes(csvIn, upperhashes)

            fIn.close()
        else:
            process = subprocess.Popen([SevenZipPath, "e", "-so",
                                       self.NSRLPath, "NSRLFile.txt"],
                                       stdout=subprocess.PIPE)
            stdout, stderr = process.communicate()
            csvIn = csv.reader(stdout.splitlines(),
                               delimiter=',',
                               skipinitialspace=True)

            outputhashes = self.searchhashes(csvIn, upperhashes)

            #     sys.stderr.write("ERROR:  Cannot open NSRL with 7-Zip!")
            #     exit(1)

        return outputhashes

    def searchhashes(self, csvreader, upperhashes):
        """
        Seaches csvreader for upperhashes, if found, returns
        hashmatches

        :param csvreader: A csv.reader object
        :param upperhashes: A list of hashes that are ALREADY upper case
                            for matching on csvreader
        :return:
        """
        hashmatches = []
        for row in csvreader:
            if row[0].upper() in upperhashes:
                hashmatches.append(row[0])
            elif row[1].upper() in upperhashes:
                hashmatches.append(row[1])
        return hashmatches

class fileintel_module(ProcessingModule) :
    name = 'fileintel_module'
    description = 'Determine the input file is malware or not through hash'

    nsrlpath = '/RDSv3_Modern_Minimal_Demo.zip'
    nsrl = NSRL(nsrlpath)

    def typeofhash(filehash):
        """
        Determines the type of the hash by the length.

        :param filehash: The hash as a string
        :results: The hash type as either MD5, SHA-1, SHA-256,
        SHA-512 or Uknown
        """
        if len(filehash) == 32:
            return('MD5')
        elif len(filehash) == 40:
            return('SHA-1')
        elif len(filehash) == 64:
            return('SHA-256')
        elif len(filehash) == 128:
            return('SHA-512')
        else:
            return('Unknown')    

    def each(self, target):
        self.results = ""
        
        with open(target) as infile:
            filehashes = infile.read().splitlines()
        Headers = []
        Data = []

        tmpdir = tempdir()
        filepath = os.path.join(tmpdir, "fileintel.csv")
        csvfile = open(filepath) 
        output = csv.writer(csvfile, lineterminator='\r\n')

        Headers.append('Input File')
        Headers.append('Hash Type?')

        NSRLHashes = []
        NSRLHashes = self.nsrl.lookup(filehashes)
        
        for filehash in filehashes:
            row = []
            row.append(filehash.upper())
            row.append(self.typeofhash(filehash))
            self.nsrl.add_headers(Headers)
            self.nsrl.add_row(NSRLHashes, filehash, row)    
            Data.append(row)
            output.writerow(Headers)
            try:
                output.writerow([unicode(field).encode('utf-8') for field in row])
            except:
                output.writerow([str(field) for field in row])        



        return True