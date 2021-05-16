from math import log2, nan
from scapy.all import IP

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

        # Keep track of total number of bytes for entropy calculations
        self.byte_num += len(byte_array)

    def calculate_entropy(self): 
        # 5-tuples with no stored packets have no entropy
        if (len(self.hist) == 0):
            return nan

        # 5-tuples with only one byte have no ambiguity 
        if (len(self.hist) == 1):
            return 0
            
        # We use the maximum possible entropy (treated as true random) of our 
          # current histogram to normalize our values
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
        # Getter
        return self.entropy_stats

    def get_layers(self, packet):
        # layer stripping obtained from: 
        #     https://stackoverflow.com/questions/13549294/get-all-the-layers-in-a-packet
        yield packet.name
        while packet.payload:
            packet = packet.payload
            yield packet.name

    def process_packet(self, packet):
        # LAYERS: 
            # 0 = ETHERNET
            # 1 = IP
            # 2 = PROTOCOL
            # ... the rest
        layers = list(self.get_layers(packet))
        if len(layers) < 2:
            return

        proto = layers[2]

        # Grab the identifying tuple
        try: 
            e_id = packet[IP].src + '_' + str(packet[proto].sport) + '_' + \
                packet[IP].dst + '_' + str(packet[proto].dport)

            e_id += '_' + proto
        except:
            # Not all protocols can work sadly
            print('Error: Cannot process packet (protocol error):')
            packet.show()
            return
        
        # Creates new entry in entropy stats if there is a new e_id
        if e_id not in self.entropy_stats:
            self.entropy_stats[e_id] = Entropy_Stat()
        
        # Turn payload into a byte array and update the histogram
        #byte_array = fields[self.idxr['tcp.payload']].split(':')
        byte_array = bytes(packet[proto].payload)
        self.entropy_stats[e_id].update_histogram(byte_array)