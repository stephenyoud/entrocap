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
    sort_type = request.args.get('sort_type', None)

    if os.path.exists(os.path.join(os.getcwd(), 'pcap_files', pcap)):
        if cur_filename != pcap:
            print(f'New File: {pcap}')
            cur_filename = pcap
            if driver.run(ec, pcap=pcap) == -1:
                return 'Failure'

        es = ec.entropy_stats
        df = pd.DataFrame()
        vals = []
        for key in es:
            tmp = []
            tmp.extend([val for val in key.split('_')])
            tmp.append(es[key].calculate_entropy())
            vals.append(tmp)
            
        df['src_ip'] = [stat[0] for stat in vals]
        df['src_port'] = [stat[1] for stat in vals]
        df['dst_ip'] = [stat[2] for stat in vals]
        df['dst_port'] = [stat[3] for stat in vals]
        df['entropy'] = [stat[4] for stat in vals]
        
        if sort_type:
            df = df.sort_values(by=sort_type)

        return render_template('pcap.html', df=df, pcap=pcap)
    else:
        return 'no'
    

if __name__ == '__main__':
    # Get command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help = 'Input File')
    args = parser.parse_args()

    app.run(debug=True)