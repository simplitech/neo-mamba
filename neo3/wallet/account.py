class Account:

    def __init__(self):
        self.address = ''
        self.label = ''
        self.is_default = True  # Acho que não é bom botar True como default ???
        self.lock = False
        self.key = ''
        self.contract = {}  # colocar new Contract() depois
        self.extra = None
