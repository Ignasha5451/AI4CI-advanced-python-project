from collections import defaultdict
from typing import Iterable
import argparse
import logging
import time
import csv
import os

from scapy.all import sniff, IP, TCP, ICMP

# Configure logging settings
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

SESSION_TIMEOUT = 2  # Define the session timeout period in seconds


def save_attack_info_to_csv(data: Iterable) -> None:
    # Save attack information to a CSV file
    with open(file_path, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(data)


def attacks_detector(packet) -> None:
    # Function to detect DDoS attacks based on incoming packets
    if IP in packet:

        src_ip = packet[IP].src

        current_time = time.time()
        packet_size = len(packet)

        attack_type = None

        # Determine the type of attack based on the source IP and packet characteristics
        if src_ip != target_ip:
            if TCP in packet and packet[TCP].flags == "S":
                attack_type = "SYN flood"
            elif ICMP in packet and len(packet) >= 500:
                attack_type = "Ping of Death"
            elif TCP in packet and packet[TCP].flags == "SA":
                attack_type = "SYN-ACK flood"
        else:
            if ICMP in packet and packet[IP].src == packet[IP].dst:
                attack_type = "Smurf"

        if attack_type:

            # Check if the time since the last packet of the same attack type is less than the session timeout
            if current_time - packet_info[(src_ip, attack_type)]["last_time"] < SESSION_TIMEOUT:
                # Update the attack info for the identified attack type
                packet_info[(src_ip, attack_type)]["count"] += 1
                packet_info[(src_ip, attack_type)]["bytes"] += packet_size
                packet_info[(src_ip, attack_type)]["last_time"] = current_time
                logger.info(f"{attack_type} attack detected from {src_ip}.")
            else:
                # If the session has timed out, save the existing attack info to CSV
                start_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(packet_info[(src_ip, attack_type)]["start_time"])
                )
                duration = max(
                    packet_info[(src_ip, attack_type)]["last_time"],
                    packet_info[(src_ip, attack_type)]["start_time"]
                ) - min(
                    packet_info[(src_ip, attack_type)]["last_time"],
                    packet_info[(src_ip, attack_type)]["start_time"]
                )
                data = [
                    start_time,
                    duration,
                    src_ip,
                    attack_type,
                    packet_info[(src_ip, attack_type)]["count"],
                    packet_info[(src_ip, attack_type)]["bytes"]
                ]
                save_attack_info_to_csv(data)

                # Reset the attack info for the new session
                packet_info[(src_ip, attack_type)]["start_time"] = current_time
                packet_info[(src_ip, attack_type)]["count"] = 1
                packet_info[(src_ip, attack_type)]["bytes"] = packet_size
                packet_info[(src_ip, attack_type)]["last_time"] = current_time

                logger.info(f"DDoS attack {attack_type} has ended.")


if __name__ == "__main__":
    # Main entry point of the script
    parser = argparse.ArgumentParser(description="Traffic monitoring for DDoS attacks")  # Create argument parser
    parser.add_argument("target_ip", type=str, help="Target IP address")
    parser.add_argument("interface", type=str, help="Interface for monitoring")
    parser.add_argument("output_csv", type=str, help="Output CSV file name")

    args = parser.parse_args()  # Parse command-line arguments
    target_ip = args.target_ip
    file_path = args.output_csv

    packet_info = defaultdict(lambda: {"start_time": time.time(), "last_time": time.time(), "count": 0, "bytes": 0})

    # Check if the output CSV file exists; if not, create it and write the header
    if not os.path.exists(args.output_csv):
        with open(file_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(
                ["Start time", "Attack Duration", "Source IP", "Attack Type", "Total Packets", "Total Bytes"])

    logger.info(f"Monitoring traffic on {args.interface}...")
    # Start sniffing packets on the specified interface and call attacks_detector for each packet
    sniff(iface=args.interface, prn=attacks_detector, store=0)

    # After stopping the sniffing, save any remaining attack information to CSV
    for src_ip_attack_type, info in packet_info.items():
        duration = max(info["last_time"], info["start_time"]) - min(info["last_time"], info["start_time"])
        data = [
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["start_time"])),
            duration,
            src_ip_attack_type[0],
            src_ip_attack_type[1],
            info["count"],
            info["bytes"]
        ]
        save_attack_info_to_csv(data)
