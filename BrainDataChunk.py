class BrainDataChunk:

    TYPES = ["B", "KB", "MB", "GB"]
    B = 0
    KB = 1
    MB = 2
    GB = 3

    def __init__(self, amount, var, updates):
        """

        :param amount:
        :param updates:
        """
        self.mean = amount
        self.variance = var
        self.num_of_updates = updates

    def update(self, other):
        """

        :param other:
        :return:
        """
        n1 = self.num_of_updates
        n2 = other.num_of_updates
        x1 = self.mean
        x2 = other.mean
        s1 = self.variance
        s2 = other.variance

        if self.num_of_updates + other.num_of_updates == 0:
            return

        total_data = self.get_total_data() + other.get_total_data()
        self.mean = int(total_data / (self.num_of_updates + other.num_of_updates))

        d2 = x2 - self.mean
        d1 = x1 - self.mean

        self.variance = (n1*(s1 + d1*d1) + n2*(s2 + d2*d2)) / (n1 + n2)
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
        size, scale_type = BrainDataChunk.get_scale_for_size(self.mean)
        variance = str(int(self.variance * 1000) / 1000)
        return "(" + str(size) + scale_type + "," + " var=" + variance + " updates=" + str(self.num_of_updates) + ")"

    def get_total_data(self):
        """

        :return:
        """
        return self.mean * self.num_of_updates

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

        variance = 0
        updates = 0
        for j in range(scale_index, len(string)):
            if string[j] == "=":
                for i in range(j + 1, len(string) - 1):
                    if string[i] == "=":
                        variance = float(string[j + 1: i - len("updates")])
                        updates = int(string[i + 1: len(string) - 1])

        return BrainDataChunk(amount * BrainDataChunk.get_mult_for_type(scale), variance, updates)

    def get_amount_data(self):
        """
        :return: amount data in chunk
        """
        return self.mean

    def get_variance(self):
        return self.variance
