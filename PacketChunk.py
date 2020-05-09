

class PacketChunk:

    def __init__(self, sender, receiver, amount, time):
        """

        :param sender:
        :param receiver:
        :param amount:
        :param time:
        """
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.time = time
