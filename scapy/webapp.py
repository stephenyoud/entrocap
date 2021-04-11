from flask import Flask, render_template
import argparse
from entropy_computer import Entropy_Computer
import driver
import os

#app = Flask(__name__, template_folder=os.path.join(os.getcwd(), 'templates'))
app = Flask(__name__)
print(app.template_folder)

@app.route('/<pcap>')
def index(pcap):
    if os.path.exists(os.path.join(os.getcwd(), 'pcap_files', pcap)):
        ec = Entropy_Computer()
        if driver.run(ec, pcap=pcap) == -1:
            return 'Failure'
        return render_template('pcap.html', stats=ec.entropy_stats)
    else:
        return 'no'
    

if __name__ == '__main__':
    # Get command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help = 'Input File')
    args = parser.parse_args()

    app.run(debug=True)