from flask import Flask, render_template, request
import argparse
from entropy_computer import Entropy_Computer
import driver
import os
import pandas as pd
import threading
import time # to delete???
import sys

from scapy.all import *

app = Flask(__name__)
ec = Entropy_Computer()
cur_filename = ''
cols = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'entropy']   

class Thread_Wrapper():
    def __init__(self):
        self.running_meta = True
        self.running = False
        self.ec = Entropy_Computer()
        self.background = threading.Thread(target=self.run, name='Background Thread')

    def stop_filter(self, x):
        if self.running:
            return False
        else:
            return True

    def callback(self, packet):
        if IP in packet:
            self.ec.process_packet(packet)

    def run(self):
        while self.running_meta:
            time.sleep(1)
            if self.running:
                sniff(filter='ip', prn=self.callback, stop_filter=self.stop_filter)

            print('waiting to run...')

        sys.exit()

tw = Thread_Wrapper()

def get_dataframe_from_entropy_stats(es):
    global cols
    df = pd.DataFrame()

    # list: [[src ip/port, dst ip/port, entropy] for all values from entropy computer]
    vals = [[val for val in key.split('_')] + [es[key].calculate_entropy()] for key in es]
        
    for i, col in enumerate(cols):
        df[col] = [stat[i] for stat in vals]

    return df

@app.route('/shutdown')
def shutdown():
    global tw
    tw.running = False
    tw.running_meta = False
    
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if shutdown is None:
        raise RuntimeError('Problem with shutdown')
    shutdown()
    return 'Shutting down server'

@app.route('/<pcap>')
def index(pcap):
    global cur_filename
    global ec
    global tw
    global cols
    sort_type = request.args.get('sort_type', None)

    tw.running = False

    if os.path.exists(os.path.join(os.getcwd(), 'pcap_files', pcap)):
        # If working on a new pcap file, update our entropy computer with new pcap
        if cur_filename != pcap:
            print(f'New File: {pcap}')
            cur_filename = pcap
            ec = Entropy_Computer()
            if driver.run(ec, pcap=pcap) == -1:
                return 'Failure'

        df = get_dataframe_from_entropy_stats(ec.entropy_stats)

        if sort_type:
            df = df.sort_values(by=sort_type)

        return render_template('pcap.html', df=df, cols=cols, pcap=pcap)
    else:
        return 'File not found'
    
@app.route('/')
def no_pcap():
    global tw 

    sort_type = request.args.get('sort_type', None)

    tw.running = True
    df = get_dataframe_from_entropy_stats(tw.ec.entropy_stats)

    if sort_type:
        df = df.sort_values(by=sort_type)
    
    return render_template('pcap.html', df=df, cols=cols, pcap='')


if __name__ == '__main__':
    # Get command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help = 'Input File')
    args = parser.parse_args()

    tw.background.start()

    app.run()