from PacketPerTime import PacketPerTime
from BrainDataChunk import BrainDataChunk
from PacketsPerInterval import PacketsPerInterval
import JsonParser
import json


IP_SET = set()


class Brain:

    def __init__(self, data_map, ip_set):
        self.data_map = data_map
        self.ip_set = ip_set

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
        return Brain(packets_per_time_dict, IP_SET)

    def update(self, packets_per_time):
            self.data_map[packets_per_time.time].update(packets_per_time)

    def get_interval(self, current_time, interval):
        packet_interval = PacketsPerInterval([])
        for i in range(interval):
            time = current_time + i
            if time not in self.data_map:
                packet_interval.update([])
            packet_interval.update(self.data_map[time])


if __name__ == '__main__':
    brain = Brain.generate_from_json(JsonParser.FILE_NAME)