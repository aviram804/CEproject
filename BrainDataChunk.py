class BrainDataChunk:

    TYPES = ["B", "KB", "MB", "GB"]
    B = 0
    KB = 1
    MB = 2
    GB = 3

    def __init__(self, data_type, amount, updates):
        """

        :param data_type:
        :param amount:
        :param updates:
        """
        self.scale_type = data_type
        self.amount_data = self.get_mult() * amount
        self.set_scale()
        self.num_of_updates = updates

    def update(self, other):
        """

        :param other:
        :return:
        """
        total_data = self.get_total_data() + other.get_total_data()
        self.amount_data = int(total_data / (self.num_of_updates + other.num_of_updates))
        self.set_scale()
        self.num_of_updates += other.num_of_updates

    def get_mult(self):
        """
        :return: multiplier with respect to the data scale
        """
        if self.scale_type == self.TYPES[self.B]:
            return 1
        if self.scale_type == self.TYPES[self.KB]:
            return 1024
        if self.scale_type == self.TYPES[self.MB]:
            return 1024 ** 2
        if self.scale_type == self.TYPES[self.GB]:
            return 1024 ** 3

    def set_scale(self):
        """
        updates the data scale and amount of data according to the fitting scale
        """
        self.amount_data, self.scale_type = BrainDataChunk.get_scale_for_size(self.amount_data)

    @staticmethod
    def get_scale_for_size(size):
        """
        updates the data scale and amount of data according to the fitting scale
        """
        for i in range(3):

            if size / 1024 < 1:
                return size, BrainDataChunk.TYPES[i]
            size = int(size / 1024)

        return size, BrainDataChunk.TYPES[BrainDataChunk.GB]

    def get_str(self):
        """
        :return: string representation
        """
        return "(" + str(self.amount_data) + self.scale_type + ", updates=" + str(self.num_of_updates) + ")"

    def get_total_data(self):
        """

        :return:
        """
        return self.amount_data * self.get_mult() * self.num_of_updates

    @staticmethod
    def get_from_str(string):
        amount = int(string[1])
        for i in range(2, len(string)):
            if not string[i].isdigit():
                break
            amount *= 10
            amount += int(string[i])
        if string[i] == "B":
            scale = "B"
        else:
            scale = string[i: i+2]
        updates = 0
        for j in range(i, len(string)):
            if string[j] == "=":
                updates = int(string[j+1: len(string) - 1])
        return BrainDataChunk(scale, amount, updates)
