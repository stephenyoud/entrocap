import os
import subprocess

# TO CHANGE: hardcoded tshark path for subprocess (needs full path for applications)
tshark_path = '/usr/bin/tshark'

def run_tshark(infile = None):
    # Setup enviro
    current_path = os.getcwd()
    if not os.path.isdir(current_path + '/temp'):
        os.mkdir(current_path + '/temp')

    out_file = os.path.join(current_path, 'temp', 'tshark.out')
    if os.path.exists(out_file):
        os.remove(out_file)

    # Create Tshark command
    cmd = f'{tshark_path}{f" -r {os.path.join(current_path, infile)}" if infile else ""} -Y tcp -Tfields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.payload'
    
    print(f'Running tshark command: {cmd}')

    with open(out_file, 'w') as f:
        process_status = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, shell=True)
        if process_status.returncode == 1:
            print(f'Tshark command failed: {process_status.stderr.decode().strip()}')
            raise RuntimeError('Tshark command failed')