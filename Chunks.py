class Chunk:

    def __init__(self, size, sender, receiver, time):
        """
        init of data chunk of size with sender ip and at given time
        :param size: np.uint64
        :param sender: string sender ip
        :param receiver: string receiver ip
        :param time: datetime object
        """
        self.size = size
        self.sender = sender
        self.receiver = receiver
        self.time = time