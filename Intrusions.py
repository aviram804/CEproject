

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

    def __init__(self, ip, time, amount_data):
        """
        :param ip: string IP
        """
        self.ip = ip
        self.time = time
        self.amount_data = amount_data

    def get_error(self):
        print("IP sent too much data ", self.ip, " at time ", self.time)

    def __eq__(self, other):
        """Overrides the default implementation"""
        if isinstance(other, IPOverSent):
            return other.ip == self.ip and other.time + 5 >= self.time >= other.time - 5
        return False

    def __hash__(self):
        return hash(str(self.ip) + str(self.time))


class IPOverReceived:
    """
    Represents IP received too much data
    """

    def __init__(self, ip, time, amount_data):
        """
        :param ip: string IP
        """
        self.ip = ip
        self.time = time
        self.amount_data = amount_data

    def get_error(self):
        print("IP received too much data ", self.ip, " at time ", self.time)

    def __eq__(self, other):
        """Overrides the default implementation"""
        if isinstance(other, IPOverReceived):
            return other.ip == self.ip and other.time + 5 >= self.time >= other.time - 5
        return False

    def __hash__(self):
        return hash(str(self.ip) + str(self.time))