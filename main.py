#!/usr/bin/env python3
import socket, struct, sys, random, ipaddress

def get_random_ip_from_cidr(cidr_block):
    """
    Get a random IP address from a CIDR block.
    """
    try:
        network = ipaddress.ip_network(cidr_block, strict=False)
        # Convert to list and pick random IP (excluding network and broadcast for /31 and smaller)
        hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
        if not hosts:
            # For /32 or single IP, just return the network address
            return str(network.network_address)
        return str(random.choice(hosts))
    except ValueError as e:
        print(f"Error parsing CIDR block '{cidr_block}': {e}")
        return None

def get_all_ips_from_cidr(cidr_block):
    """
    Get all IP addresses from a CIDR block.
    """
    try:
        network = ipaddress.ip_network(cidr_block, strict=False)
        # Convert to list of all IPs (excluding network and broadcast for /31 and smaller)
        hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
        if not hosts:
            # For /32 or single IP, just return the network address
            return [str(network.network_address)]
        return [str(ip) for ip in hosts]
    except ValueError as e:
        print(f"Error parsing CIDR block '{cidr_block}': {e}")
        return []

def scan_udp_closed(target, port_start, port_end, timeout):
    """
    For each UDP port in [port_start..port_end]:
      1) send an empty UDP packet
      2) listen on a raw ICMP socket for up to `timeout` seconds
      3) if an ICMP Type=3/Code=3 quoting that port arrives, print it
    """
    print(f"  Scanning {target} ports {port_start}–{port_end}")
    
    # Raw socket to receive ICMP replies
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_sock.settimeout(timeout)
    except PermissionError:
        print(f"  Error: Need root privileges to create raw socket for {target}")
        return

    ports = list(range(port_start, port_end + 1))
    random.shuffle(ports)

    for port in ports:
        # Fire-and-forget UDP socket
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.sendto(b'', (target, port))
        except Exception as e:
            print(f"  Port {port}: UDP send error - {e}")
            continue

        try:
            # Wait for any ICMP reply
            data, addr = icmp_sock.recvfrom(1024)
        except socket.timeout:
            # No ICMP within timeout → assume no unreachable reply
            print(f"  Port {port}: ICMP timeout")
            pass
        else:
            # Parse ICMP header (starts at byte 20 of the IP packet)
            icmp_type, icmp_code = data[20], data[21]

            # The original IP header is echoed starting at byte 28,
            # so the original UDP header starts at byte 28+20 = 48
            # UDP header: [src port(2), dst port(2), ...]
            orig_udp_header = data[48:52]
            orig_dst_port = struct.unpack('!H', orig_udp_header[2:4])[0]

            if icmp_type == 3 and icmp_code == 3 and orig_dst_port == port:
                print(f"  Port {port}: ICMP type=3/code=3 (closed)")

        udp_sock.close()

    icmp_sock.close()

def scan_from_cidr_file(cidr_file, port_start, port_end, timeout, scan_all=False):
    """
    Read CIDR blocks from file, select random IP from each block (or all IPs), and scan it.
    """
    try:
        with open(cidr_file, 'r') as f:
            cidr_blocks = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"Error: File '{cidr_file}' not found")
        return
    except Exception as e:
        print(f"Error reading file '{cidr_file}': {e}")
        return

    if not cidr_blocks:
        print(f"No CIDR blocks found in '{cidr_file}'")
        return

    print(f"Found {len(cidr_blocks)} CIDR block(s) in '{cidr_file}'")
    mode = "all IPs" if scan_all else "random IP from each block"
    print(f"Mode: Scanning {mode}")
    
    total_ips_scanned = 0
    
    for i, cidr_block in enumerate(cidr_blocks, 1):
        print(f"\n[{i}/{len(cidr_blocks)}] Processing CIDR block: {cidr_block}")
        
        if scan_all:
            # Get all IPs from this CIDR block
            target_ips = get_all_ips_from_cidr(cidr_block)
            if not target_ips:
                continue
                
            print(f"  Found {len(target_ips)} IP(s) to scan")
            
            # Warn for large CIDR blocks
            if len(target_ips) > 1000:
                print(f"  WARNING: Large CIDR block with {len(target_ips)} IPs. This may take a while!")
                response = input("  Continue? (y/N): ").strip().lower()
                if response != 'y':
                    print("  Skipping this CIDR block")
                    continue
            
            # Scan each IP in the block
            for j, target_ip in enumerate(target_ips, 1):
                print(f"  [{j}/{len(target_ips)}] Scanning IP: {target_ip}")
                scan_udp_closed(target_ip, port_start, port_end, timeout)
                total_ips_scanned += 1
        else:
            # Get random IP from this CIDR block (original behavior)
            target_ip = get_random_ip_from_cidr(cidr_block)
            if target_ip is None:
                continue
                
            print(f"  Selected random IP: {target_ip}")
            scan_udp_closed(target_ip, port_start, port_end, timeout)
            total_ips_scanned += 1
    
    print(f"\nScan complete. Total IPs scanned: {total_ips_scanned}")

def scan_single_cidr(cidr_block, port_start, port_end, timeout, scan_all=False):
    """
    Scan a single CIDR block - either random IP or all IPs.
    """
    print(f"Processing CIDR block: {cidr_block}")
    
    if scan_all:
        target_ips = get_all_ips_from_cidr(cidr_block)
        if not target_ips:
            return
            
        print(f"Found {len(target_ips)} IP(s) to scan")
        
        # Warn for large CIDR blocks
        if len(target_ips) > 1000:
            print(f"WARNING: Large CIDR block with {len(target_ips)} IPs. This may take a while!")
            response = input("Continue? (y/N): ").strip().lower()
            if response != 'y':
                print("Scan cancelled")
                return
        
        # Scan each IP in the block
        for i, target_ip in enumerate(target_ips, 1):
            print(f"[{i}/{len(target_ips)}] Scanning IP: {target_ip}")
            scan_udp_closed(target_ip, port_start, port_end, timeout)
    else:
        target_ip = get_random_ip_from_cidr(cidr_block)
        if target_ip:
            print(f"Selected random IP: {target_ip}")
            scan_udp_closed(target_ip, port_start, port_end, timeout)

if __name__ == "__main__":
    # Check for --all flag
    scan_all = False
    args = sys.argv[1:]
    
    if '--all' in args or '-a' in args:
        scan_all = True
        # Remove the flag from arguments
        args = [arg for arg in args if arg not in ['--all', '-a']]
    
    if len(args) < 3:
        print(f"Usage: sudo {sys.argv[0]} [--all|-a] <target_or_cidr_file> <start_port> <end_port> [timeout_sec]")
        print(f"  Single IP:   sudo {sys.argv[0]} 192.168.1.1 80 80")
        print(f"  CIDR file:   sudo {sys.argv[0]} cidrs.txt 80 443")
        print(f"  CIDR block:  sudo {sys.argv[0]} 192.168.1.0/24 22 22")
        print(f"  All IPs:     sudo {sys.argv[0]} --all cidrs.txt 80 443")
        print(f"  File format: One CIDR block per line (e.g., '192.168.1.0/24')")
        print(f"")
        print(f"Options:")
        print(f"  --all, -a    Scan all IPs in each CIDR block (instead of random)")
        sys.exit(1)

    target_or_file = args[0]
    start          = int(args[1])
    end            = int(args[2])
    timeout        = float(args[3]) if len(args) == 4 else 0.15

    # Check if first argument is a file or an IP address
    if target_or_file.endswith('.txt') or '/' in target_or_file:
        # Assume it's either a file or a CIDR block
        try:
            # First try to parse as CIDR block
            ipaddress.ip_network(target_or_file, strict=False)
            # If successful, treat as single CIDR block
            print(f"Treating '{target_or_file}' as single CIDR block")
            scan_single_cidr(target_or_file, start, end, timeout, scan_all)
        except ValueError:
            # Not a valid CIDR, assume it's a file
            print(f"Treating '{target_or_file}' as CIDR file")
            scan_from_cidr_file(target_or_file, start, end, timeout, scan_all)
    else:
        # Assume it's a single IP address
        mode_text = f", timeout={timeout}s"
        print(f"Scanning single target {target_or_file}, ports {start}–{end}{mode_text}…")
        scan_udp_closed(target_or_file, start, end, timeout)