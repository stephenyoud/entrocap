from tshark_wrapper import run_tshark
import entropy_computer

#run_tshark('tshark.out', 'hart_ip.pcap')

ec = entropy_computer.Entropy_Computer()
ec.process_file(filename='tshark.out')

for id in ec.entropy_stats:
    print(f'TUPLE: {id}: {ec.entropy_stats[id].calculate_entropy()}')