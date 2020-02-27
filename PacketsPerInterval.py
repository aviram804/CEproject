import PacketPerTime
TIME_INTERVAL = 5


class PacketsPerInterval:

    def __init__(self, packets):
        """

        :param packets:
        """
        self.packets = packets
        self.oldest = 0

    def update(self, packet_per_time):
        """

        :param packet_per_time:
        :return:
        """
        self.packets[self.oldest] = packet_per_time
        self.oldest = (self.oldest + 1) % TIME_INTERVAL
