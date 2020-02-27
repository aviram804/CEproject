TYPES = ["B", "KB", "MB", "GB"]
B = 0
KB = 1
MB = 2
GB = 3


class BrainDataChunk:

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
        if self.scale_type == TYPES[B]:
            return 1
        if self.scale_type == TYPES[KB]:
            return 1024
        if self.scale_type == TYPES[MB]:
            return 1024 ** 2
        if self.scale_type == TYPES[GB]:
            return 1024 ** 3

    def set_scale(self):
        """
        updates the data scale and amount of data according to the fitting scale
        """
        i = 0
        while i < 3:
            self.scale_type = TYPES[i]
            if self.amount_data / 1024 < 1:
                return
            i += 1
            self.amount_data = int(self.amount_data / 1024)
        self.scale_type = TYPES[i]

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




# dict1 = {
#          "123.123.123.123": BrainDataChunk("B", 1212, 12),
#          "173.123.123.125": BrainDataChunk("B", 457645, 3),
#          "123.163.123.127": BrainDataChunk("B", 12243512, 35),
#          "123.123.143.122": BrainDataChunk("B", 1254435312, 365)
#          }
#
# dict2 = {
#          "123.123.123.123": BrainDataChunk("B", 12, 32),
#          "113.183.123.125": BrainDataChunk("B", 121352, 5),
#          "143.723.543.123": BrainDataChunk("B", 121223, 3),
#          "123.163.123.127": BrainDataChunk("B", 121122, 1)
#          }
#
# map = {3 : dict1, 4 : dict2}
#
# b = BrainDataChunk("B", 565466, 34)
# d = BrainDataChunk("B", 6, 57)
# print(b.get_str())
# d.update(b)
# print(d.get_str())
