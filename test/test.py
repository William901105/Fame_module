from fame.core.module import ProcessingModule

class Test(ProcessingModule):
    name = "Test_for_updating"
    description = "output an txt"

    acts_on=[]#none means all type
    generates=["txt"]


    def each(self, target):
        self.add_support_file("output file","test.txt")
        return True