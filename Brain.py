from PacketPerTime import PacketPerTime
from BrainDataChunk import BrainDataChunk
import json

class Brain:

    def __init__(self, data_map):
        self.data_map = data_map

    def generate_jason(self, dest):
        """
        :param dest: path to place csv
        :return:
        """
        general_dict = {}
        for key, value in self.data_map.items():
            general_dict[key] = value.dump()
        with open(dest, 'w') as json_file:
            json.dump(general_dict, json_file)

    @staticmethod
    def generate_from_json(dest):
        """
        :param dest: path to place csv
        :return:
        """
        packets_per_time_dict = {}
        with open(dest, 'r') as f:
            d = json.load(f)
        for key, value in d.items():
            packets_per_time_dict[key] = PacketPerTime.from_json(value, key)
        return Brain(packets_per_time_dict)

    def update(self, packets_per_time_interval):
        for packet in packets_per_time_interval.packets:
            self.data_map[packet.time].update(packet)




if __name__ == '__main__':
    dict1 = {
        "123.123.123.123": (BrainDataChunk("B", 1212, 12), BrainDataChunk("B", 1212, 12)),
        "173.123.123.125": (BrainDataChunk("B", 457645, 3),BrainDataChunk("B", 457645, 3)),
        "123.163.123.127": (BrainDataChunk("B", 12243512, 35), BrainDataChunk("B", 12243512, 35)),
        "123.123.143.122": (BrainDataChunk("B", 1254435312, 365), BrainDataChunk("B", 1254435312, 365))
    }

    dict2 = {
        "123.123.123.123": (BrainDataChunk("B", 12, 32),BrainDataChunk("B", 12, 32)),
        "113.183.123.125": (BrainDataChunk("B", 121352, 5),BrainDataChunk("B", 121352, 5)),
        "143.723.543.123": (BrainDataChunk("B", 121223, 3),BrainDataChunk("B", 121223, 3)),
        "123.163.123.127": (BrainDataChunk("B", 121122, 1),BrainDataChunk("B", 121122, 1))
    }

    map = {1: PacketPerTime(dict1, 1), 2: PacketPerTime(dict2, 2)}
    b = Brain(map)
    newb = Brain.generate_from_json("C:\\Users\\aviram\\PycharmProjects\\engineerProject\\data")
    newb.generate_jason("C:\\Users\\aviram\\PycharmProjects\\engineerProject\\data2")