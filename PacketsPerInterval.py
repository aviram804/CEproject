import PacketPerTime


class PacketsPerInterval:

    INTERVAL = 5

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
        if len(self.packets) < self.INTERVAL:
            self.packets.append(packet_per_time)
            return None
        to_throw = self.packets[self.oldest]
        self.packets[self.oldest] = packet_per_time
        self.oldest = (self.oldest + 1) % self.INTERVAL
        return to_throw
