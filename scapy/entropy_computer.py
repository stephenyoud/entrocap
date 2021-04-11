from math import log2, nan
from scapy.all import IP, TCP

class Entropy_Stat():
    def __init__(self):
        self.hist = {}
        self.byte_num = 0

    def update_histogram(self, byte_array):
        # Updates histogram
        for b in byte_array:
            if b in self.hist:
                self.hist[b] += 1
            else:
                self.hist[b] = 1

        self.byte_num += len(byte_array)

    def calculate_entropy(self): 
        if (len(self.hist) == 0):
            return nan

        if (len(self.hist) == 1):
            return 0
            
        l = self.byte_num
        max_entro = log2(len(self.hist))
        
        # SUMMATION OF [prob of byte b * log2(1/prob of byte b)] for all bytes
        entro = sum([self.hist[b]/l * log2(1/(self.hist[b]/l)) for b in self.hist])
        # Normalizing makes it much easier to compare between multiple entropies
        normalized_entro = entro / max_entro
        return normalized_entro


class Entropy_Computer():
    def __init__(self):
        self.entropy_stats = {}     # 5-tuple: entropy_stat

    def get_stats(self):
        return self.entropy_stats

    def process_packet(self, packet):
        # Grab the identifying tuple
        e_id = packet[IP].src + '_' + str(packet[TCP].sport) + '_' + \
            packet[IP].dst + '_' + str(packet[TCP].dport)
        
        # Creates new entry in entropy stats if there is a new e_id
        if e_id not in self.entropy_stats:
            self.entropy_stats[e_id] = Entropy_Stat()
        
        # Turn payload into a byte array and update the histogram
        #byte_array = fields[self.idxr['tcp.payload']].split(':')
        byte_array = bytes(packet[TCP].payload)
        self.entropy_stats[e_id].update_histogram(byte_array)