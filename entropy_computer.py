import os
import codecs
from math import log2

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
        l = self.byte_num
        max_entro = log2(len(self.hist))
        # SUMMATION OF [prob of byte b * log2(1/prob of byte b)] for all bytes
        entro = sum([self.hist[b]/l * log2(1/(self.hist[b]/l)) for b in self.hist])
        # Normalizing makes it much easier to compare between multiple entropies
        normalized_entro = entro / max_entro
        return normalized_entro


class Entropy_Computer():
    def __init__(self):
        self.entropy_stats = {}     # 5-tuple: [statistics]
                                               # histogram

        self.column_names = [  
            'ip.src',
            'ip.dst',
            'tcp.srcport',
            'tcp.dstport',
            'tcp.payload'
        ]

        self.idxr = {key: index for index, key in enumerate(self.column_names)}

    def decode_payload(self, payload):
        # Used for when wanting to see what a payload looks like.
        # Turns byte array to string, decodes it into hex, 
        #   and decodes it once again into ascii.
        as_string = ''.join(p for p in payload)
        as_hex = codecs.decode(as_string, 'hex')
        as_ascii = as_hex.decode('ascii', errors = 'ignore')
        return as_ascii

    def process_file(self, filename):
        # Opens tmp file
        with open(os.path.join('temp', filename), 'r') as f:
            output_lines = f.read().split('\n')

        # Processes each packet individually
        for line in output_lines:
            fields = line.split('\t')

            # Ignore empty rows or fields w/o payloads
            if fields[0] == '' or fields[self.idxr['tcp.payload']] == '':
                continue
            
            # Grab the identifying tuple
            e_id = fields[self.idxr['ip.src']] + '_' + fields[self.idxr['tcp.srcport']] + \
                '_' + fields[self.idxr['ip.src']] + '_' + fields[self.idxr['tcp.dstport']]

            # Creates new entry in entropy stats if there is a new e_id
            if e_id not in self.entropy_stats:
                self.entropy_stats[e_id] = Entropy_Stat()
            
            # Turn payload into a byte array and update the histogram
            byte_array = fields[self.idxr['tcp.payload']].split(':')
            self.entropy_stats[e_id].update_histogram(byte_array)