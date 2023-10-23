from fame.core.module import ProcessingModule

class fileintel_module(ProcessingModule) :
    name = 'fileintel_module'
    description = 'Determine the input file is malware or not through hash'
    def each(self, target):
        
        return True