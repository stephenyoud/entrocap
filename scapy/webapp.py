from flask import Flask, render_template, request
import argparse
from entropy_computer import Entropy_Computer
import driver
import os
import pandas as pd
import threading
import time
import sys

from scapy.all import *

app = Flask(__name__)
ec = Entropy_Computer()
cur_filename = ''
# Columns. These can be indexed to ensure commonality between continuous and pcap input
cols = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'entropy']   

class Thread_Wrapper():
    def __init__(self):
        self.running_meta = True   # holds if program itself is running
        self.running = False       # holds if background thread should be running or not
        self.ec = Entropy_Computer()
        self.background = threading.Thread(target=self.run, name='Background Thread')

    def stop_filter(self, x):
        # This function acts as the filter function to stop our sniff or not.
        # If running is set to true, we return false because we don't want to stop yet.
        # Currently, I am not simply returning 'not self.running' because I may want to
          # add additional functionality in the future. 
        if self.running:
            return False
        else:
            return True

    def callback(self, packet):
        # Additional check that packet is an IP packet. Run packet processing on our EC
        if IP in packet:
            self.ec.process_packet(packet)

    def run(self):
        # Driver program for background process. Runs while running_meta is true, and
          # calls sys.exit() to end thread once it is not (triggered by shutdown on webapp)
        while self.running_meta:
            time.sleep(1)
            if self.running:
                sniff(filter='ip', prn=self.callback, stop_filter=self.stop_filter)

            print('waiting to run...')

        sys.exit()

# Define gloabl thread wrapper accessable by webapp
tw = Thread_Wrapper()

def get_dataframe_from_entropy_stats(es):
    # Converts entropy stats to dataframe
    global cols
    df = pd.DataFrame()

    # list: [[src ip/port, dst ip/port, protocol, entropy] for all values from entropy computer]
    vals = [[val for val in key.split('_')] + [es[key].calculate_entropy()] for key in es]
        
    for i, col in enumerate(cols):
        df[col] = [stat[i] for stat in vals]

    return df

@app.route('/shutdown')
def shutdown():
    # Healthily shutdown flask program. Usually, ctrl-C works well enough, but 
      # this will not halt the background thread and program will run indefinetly. 
    global tw
    tw.running = False          # halts current collection process
    tw.running_meta = False     # halts thread from running entirely 
    
    # Shutdown from within app obtained from: 
      # https://stackoverflow.com/questions/15562446/how-to-stop-flask-application-without-using-ctrl-c
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

    # Grab sort values, defaulted to none
    sort_type = request.args.get('sort_type', None)

    # Halt background collection process
    tw.running = False

    # Check that input pcap file exists
    if os.path.exists(os.path.join(os.getcwd(), 'pcap_files', pcap)):
        # If working on a new pcap file, update our entropy computer with new pcap.
        # This is done to prevent needless caluclation of the same pcap over and over again
        if cur_filename != pcap:
            print(f'New File: {pcap}')
            cur_filename = pcap
            ec = Entropy_Computer()
            if driver.run(ec, pcap=pcap) == -1:
                return 'Failure'

        # Get dataframe and sort (if needed)
        df = get_dataframe_from_entropy_stats(ec.entropy_stats)

        if sort_type:
            df = df.sort_values(by=sort_type)

        # Return HTML code from template w/ passed in variables
        return render_template('pcap.html', df=df, cols=cols, pcap=pcap)
    else:
        return 'File not found'
    
@app.route('/')
def no_pcap():
    global tw 

    # Grab sort values, defaulted to none
    sort_type = request.args.get('sort_type', None)

    # Set passive collection to true and grab the current dataframe. 
    # The entropy computer will constantly run in the background while running
      # is set to true, but the html page will only update when refreshed because
      # this is where to stats are obtained and printed to the screen.
    tw.running = True
    df = get_dataframe_from_entropy_stats(tw.ec.entropy_stats)

    # Sort if needed
    if sort_type:
        df = df.sort_values(by=sort_type)
    
    # Return HTML code from template w/ passed in variables
    return render_template('pcap.html', df=df, cols=cols, pcap='')


if __name__ == '__main__':
    # Start background process and run the flask application
    tw.background.start()
    app.run()