

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
