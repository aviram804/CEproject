

class FoundNewIP:
    """
    Represents New IP entered to database
    """

    def __init__(self, ip):
        """
        :param ip: string IP
        """
        self.ip = ip

    def get_error(self):
        print("New IP Warning ", self.ip)


class FoundMaliciousIP:
    """
    Represents Malicious IP entered to database
    """

    def __init__(self, ip):
        """
        :param ip: string IP
        """
        self.ip = ip

    def get_error(self):
        print("Malicious IP Warning ", self.ip)


class IPOverSent:
    """
    Represents IP sent too much data
    """

    def __init__(self, ip, time):
        """
        :param ip: string IP
        """
        self.ip = ip
        self.time = time

    def get_error(self):
        print("IP sent too much data ", self.ip, " at time ", self.time)


class IPOverReceived:
    """
    Represents IP received too much data
    """

    def __init__(self, ip, time):
        """
        :param ip: string IP
        """
        self.ip = ip
        self.time = time

    def get_error(self):
        print("IP received too much data ", self.ip, " at time ", self.time)
