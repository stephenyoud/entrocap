import os

class Entropy_Computer():
    def __init__(self):
        self.entropy_stats = {}     # 5-tuple: [statistics]

        self.column_names = [  
            'ip.src',
            'ip.dst',
            'tcp.srcport',
            'tcp.dstport',
            'tcp.payload'
        ]

        self.idxr = {key: index for index, key in enumerate(self.column_names)}

    def process_file(self, filename):
        with open(os.path.join('temp', filename), 'r') as f:
            output_lines = f.read().split('\n')

        for line in output_lines:
            fields = line.split('\t')

            if fields[0] == '' or fields[self.idxr['tcp.payload']] == '':
                continue

            print(fields)