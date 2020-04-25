class BrainDataChunk:

    TYPES = ["B", "KB", "MB", "GB"]
    B = 0
    KB = 1
    MB = 2
    GB = 3

    def __init__(self, amount, updates):
        """

        :param amount:
        :param updates:
        """
        self.amount_data = amount
        self.num_of_updates = updates

    def update(self, other):
        """

        :param other:
        :return:
        """
        total_data = self.get_total_data() + other.get_total_data()
        if self.num_of_updates + other.num_of_updates == 0:
            return
        self.amount_data = int(total_data / (self.num_of_updates + other.num_of_updates))
        self.num_of_updates += other.num_of_updates

    @staticmethod
    def get_mult_for_type(scale_type):
        """
        :return: multiplier with respect to the data scale
        """
        if scale_type == BrainDataChunk.TYPES[BrainDataChunk.B]:
            return 1
        if scale_type == BrainDataChunk.TYPES[BrainDataChunk.KB]:
            return 1024
        if scale_type == BrainDataChunk.TYPES[BrainDataChunk.MB]:
            return 1024 ** 2
        if scale_type == BrainDataChunk.TYPES[BrainDataChunk.GB]:
            return 1024 ** 3

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
        size, scale_type = BrainDataChunk.get_scale_for_size(self.amount_data)
        return "(" + str(size) + scale_type + ", updates=" + str(self.num_of_updates) + ")"

    def get_total_data(self):
        """

        :return:
        """
        return self.amount_data * self.num_of_updates

    @staticmethod
    def get_from_str(string):
        amount = int(string[1])

        scale_index = 0
        for i in range(2, len(string)):
            if not string[i].isdigit():
                scale_index = i
                break
            amount *= 10
            amount += int(string[i])
        if string[scale_index] == "B":
            scale = "B"
        else:
            scale = string[scale_index: scale_index+2]
        updates = 0
        for j in range(scale_index, len(string)):
            if string[j] == "=":
                updates = int(string[j+1: len(string) - 1])
        if BrainDataChunk.get_mult_for_type(scale) is None:
            print("hi")
            print(scale)

        return BrainDataChunk(amount * BrainDataChunk.get_mult_for_type(scale), updates)

    def get_amount_data(self):
        """
        :return: amount data in chunk
        """
        return self.amount_data
