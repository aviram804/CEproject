import numpy as np
import Chunks
"""

*** C h u n k s  B a s e  ***

"""
class ChunksBase:

    def __init__(self):
        """
        init of database that holds all chuncks
        """
        self.chunks = []

    def add(self, chunk):
        """
        adding a new chunk to the chunksbase
        :param chunk: chunk object - holds all the data of one packet
        :return:
        """
        self.detect_anomaly(chunk)
        self.chunks.append(chunk)

    def detect_anomaly(self, chunk):
        """
        try to detect anomaly behavior of a packet that coming from some ip
        :param chunk: chunk object - holds all the data of one packet
        :return:
        """
        pass