from fame.core.module import ProcessingModule

class Test(ProcessingModule):
    name = "Test"
    description = "output an txt"

    acts_on=[]#none means all type
    


    def each(self, target):
        print("succeed")
        self.add_support_file("output file","test.txt")
        return True