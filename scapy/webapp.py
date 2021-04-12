from flask import Flask, render_template, request
import argparse
from entropy_computer import Entropy_Computer
import driver
import os
import pandas as pd

#app = Flask(__name__, template_folder=os.path.join(os.getcwd(), 'templates'))
app = Flask(__name__)
ec = Entropy_Computer()
cur_filename = ''

@app.route('/<pcap>')
def index(pcap):
    global cur_filename
    global ec
    sort_type = request.args.get('sort_type', None)

    if os.path.exists(os.path.join(os.getcwd(), 'pcap_files', pcap)):
        # If working on a new pcap file, update our entropy computer with new pcap
        if cur_filename != pcap:
            print(f'New File: {pcap}')
            cur_filename = pcap
            ec = Entropy_Computer()
            if driver.run(ec, pcap=pcap) == -1:
                return 'Failure'

        es = ec.entropy_stats
        cols = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'entropy']
        df = pd.DataFrame()

        # list: [[src ip/port, dst ip/port, entropy] for all values from entropy computer]
        vals = [[val for val in key.split('_')] + [es[key].calculate_entropy()] for key in es]
            
        for i, col in enumerate(cols):
            df[col] = [stat[i] for stat in vals]

        if sort_type:
            df = df.sort_values(by=sort_type)

        return render_template('pcap.html', df=df, cols=cols, pcap=pcap)
    else:
        return 'no'
    

if __name__ == '__main__':
    # Get command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help = 'Input File')
    args = parser.parse_args()

    app.run(debug=True)