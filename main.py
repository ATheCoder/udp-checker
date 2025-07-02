#!/usr/bin/env python3
import socket, struct, sys, random, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

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

# Thread-local storage for sockets to avoid conflicts
thread_local = threading.local()

def get_icmp_socket(timeout):
    """
    Get a thread-local raw ICMP socket.
    """
    if not hasattr(thread_local, 'icmp_sock'):
        try:
            thread_local.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            thread_local.icmp_sock.settimeout(timeout)
        except PermissionError:
            thread_local.icmp_sock = None
    return thread_local.icmp_sock

def scan_udp_closed(target, port_start, port_end, timeout, thread_safe=False):
    """
    For each UDP port in [port_start..port_end]:
      1) send an empty UDP packet
      2) listen on a raw ICMP socket for up to `timeout` seconds
      3) if an ICMP Type=3/Code=3 quoting that port arrives, print it
    """
    prefix = f"[{threading.current_thread().name}] " if thread_safe else "  "
    print(f"{prefix}Scanning {target} ports {port_start}–{port_end}")
    
    # Get thread-local ICMP socket if in thread-safe mode
    if thread_safe:
        icmp_sock = get_icmp_socket(timeout)
        if icmp_sock is None:
            print(f"{prefix}Error: Need root privileges to create raw socket for {target}")
            return
    else:
        # Original single-threaded approach
        try:
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_sock.settimeout(timeout)
        except PermissionError:
            print(f"{prefix}Error: Need root privileges to create raw socket for {target}")
            return

    ports = list(range(port_start, port_end + 1))
    random.shuffle(ports)

    for port in ports:
        # Fire-and-forget UDP socket
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.sendto(b'', (target, port))
        except Exception as e:
            print(f"{prefix}Port {port}: UDP send error - {e}")
            continue

        try:
            # Wait for any ICMP reply
            data, addr = icmp_sock.recvfrom(1024)
        except socket.timeout:
            # No ICMP within timeout → assume no unreachable reply
            print(f"{prefix}Port {port}: ICMP timeout")
            pass
        else:
            print(f'Got ICMP reply for port {port} on IP {addr[0]}')
            # Parse ICMP header (starts at byte 20 of the IP packet)
            icmp_type, icmp_code = data[20], data[21]

            # The original IP header is echoed starting at byte 28,
            # so the original UDP header starts at byte 28+20 = 48
            # UDP header: [src port(2), dst port(2), ...]
            orig_udp_header = data[48:52]
            orig_dst_port = struct.unpack('!H', orig_udp_header[2:4])[0]

            if icmp_type == 3 and icmp_code == 3 and orig_dst_port == port:
                print(f"{prefix}Port {port}: ICMP type=3/code=3 (closed)")
            else:
                print(f"{prefix}Port {port}: ICMP type={icmp_type}/code={icmp_code} (open)")

        udp_sock.close()

    if not thread_safe:
        icmp_sock.close()

def scan_ip_worker(args):
    """
    Worker function for parallel IP scanning.
    """
    target_ip, port_start, port_end, timeout, scan_id = args
    scan_udp_closed(target_ip, port_start, port_end, timeout, thread_safe=True)
    return f"Completed scan for {target_ip}"

def scan_cidr_worker(args):
    """
    Worker function for parallel CIDR block processing.
    """
    cidr_block, port_start, port_end, timeout, scan_all, max_workers = args
    
    print(f"[{threading.current_thread().name}] Processing CIDR block: {cidr_block}")
    
    if scan_all:
        target_ips = get_all_ips_from_cidr(cidr_block)
        if not target_ips:
            return f"No IPs found in {cidr_block}"
            
        print(f"[{threading.current_thread().name}] Found {len(target_ips)} IP(s) to scan in {cidr_block}")
        
        # Parallel IP scanning within this CIDR block
        if len(target_ips) > 1 and max_workers > 1:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(target_ips))) as ip_executor:
                ip_tasks = []
                for i, target_ip in enumerate(target_ips):
                    task_args = (target_ip, port_start, port_end, timeout, f"{cidr_block}_{i}")
                    ip_tasks.append(ip_executor.submit(scan_ip_worker, task_args))
                
                # Wait for all IP scans to complete
                for future in as_completed(ip_tasks):
                    try:
                        result = future.result()
                    except Exception as e:
                        print(f"[{threading.current_thread().name}] Error in IP scan: {e}")
        else:
            # Sequential scanning for small blocks or single-threaded mode
            for target_ip in target_ips:
                scan_udp_closed(target_ip, port_start, port_end, timeout, thread_safe=True)
                
        return f"Completed CIDR block {cidr_block} with {len(target_ips)} IPs"
    else:
        target_ip = get_random_ip_from_cidr(cidr_block)
        if target_ip:
            print(f"[{threading.current_thread().name}] Selected random IP: {target_ip}")
            scan_udp_closed(target_ip, port_start, port_end, timeout, thread_safe=True)
            return f"Completed random IP scan for {cidr_block}: {target_ip}"
        else:
            return f"Failed to get IP from {cidr_block}"

def scan_from_cidr_file(cidr_file, port_start, port_end, timeout, scan_all=False, max_workers=4):
    """
    Read CIDR blocks from file, select random IP from each block (or all IPs), and scan it.
    Now with parallel processing support.
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
    parallel_info = f" (parallel with {max_workers} workers)" if max_workers > 1 else " (sequential)"
    print(f"Mode: Scanning {mode}{parallel_info}")
    
    start_time = time.time()
    
    if max_workers > 1 and len(cidr_blocks) > 1:
        # Parallel CIDR block processing
        with ThreadPoolExecutor(max_workers=min(max_workers, len(cidr_blocks))) as executor:
            tasks = []
            for cidr_block in cidr_blocks:
                task_args = (cidr_block, port_start, port_end, timeout, scan_all, max_workers)
                tasks.append(executor.submit(scan_cidr_worker, task_args))
            
            # Process completed tasks
            completed = 0
            for future in as_completed(tasks):
                try:
                    result = future.result()
                    completed += 1
                    print(f"[MAIN] Progress: {completed}/{len(cidr_blocks)} CIDR blocks completed")
                except Exception as e:
                    print(f"[MAIN] Error processing CIDR block: {e}")
                    completed += 1
    else:
        # Sequential processing (original behavior)
        total_ips_scanned = 0
        
        for i, cidr_block in enumerate(cidr_blocks, 1):
            print(f"\n[{i}/{len(cidr_blocks)}] Processing CIDR block: {cidr_block}")
            
            if scan_all:
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
                target_ip = get_random_ip_from_cidr(cidr_block)
                if target_ip is None:
                    continue
                    
                print(f"  Selected random IP: {target_ip}")
                scan_udp_closed(target_ip, port_start, port_end, timeout)
                total_ips_scanned += 1
        
        print(f"\nScan complete. Total IPs scanned: {total_ips_scanned}")
    
    end_time = time.time()
    print(f"\nTotal scan time: {end_time - start_time:.2f} seconds")

def scan_single_cidr(cidr_block, port_start, port_end, timeout, scan_all=False, max_workers=4):
    """
    Scan a single CIDR block - either random IP or all IPs.
    Now with parallel processing support.
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
        
        start_time = time.time()
        
        if max_workers > 1 and len(target_ips) > 1:
            # Parallel IP scanning
            with ThreadPoolExecutor(max_workers=min(max_workers, len(target_ips))) as executor:
                tasks = []
                for i, target_ip in enumerate(target_ips):
                    task_args = (target_ip, port_start, port_end, timeout, f"ip_{i}")
                    tasks.append(executor.submit(scan_ip_worker, task_args))
                
                # Process completed tasks
                completed = 0
                for future in as_completed(tasks):
                    try:
                        result = future.result()
                        completed += 1
                        print(f"[MAIN] Progress: {completed}/{len(target_ips)} IPs completed")
                    except Exception as e:
                        print(f"[MAIN] Error scanning IP: {e}")
                        completed += 1
        else:
            # Sequential scanning
            for i, target_ip in enumerate(target_ips, 1):
                print(f"[{i}/{len(target_ips)}] Scanning IP: {target_ip}")
                scan_udp_closed(target_ip, port_start, port_end, timeout)
        
        end_time = time.time()
        print(f"\nScan time: {end_time - start_time:.2f} seconds")
    else:
        target_ip = get_random_ip_from_cidr(cidr_block)
        if target_ip:
            print(f"Selected random IP: {target_ip}")
            scan_udp_closed(target_ip, port_start, port_end, timeout)

if __name__ == "__main__":
    # Check for flags
    scan_all = False
    max_workers = 4  # Default number of parallel workers
    args = sys.argv[1:]
    
    # Parse flags
    if '--all' in args or '-a' in args:
        scan_all = True
        args = [arg for arg in args if arg not in ['--all', '-a']]
    
    # Parse parallel workers flag
    if '--workers' in args or '-w' in args:
        try:
            idx = args.index('--workers') if '--workers' in args else args.index('-w')
            max_workers = int(args[idx + 1])
            args = args[:idx] + args[idx + 2:]  # Remove both flag and value
        except (ValueError, IndexError):
            print("Error: --workers/-w flag requires a numeric value")
            sys.exit(1)
    
    if len(args) < 3:
        print(f"Usage: sudo {sys.argv[0]} [--all|-a] [--workers|-w N] <target_or_cidr_file> <start_port> <end_port> [timeout_sec]")
        print(f"  Single IP:   sudo {sys.argv[0]} 192.168.1.1 80 80")
        print(f"  CIDR file:   sudo {sys.argv[0]} cidrs.txt 80 443")
        print(f"  CIDR block:  sudo {sys.argv[0]} 192.168.1.0/24 22 22")
        print(f"  All IPs:     sudo {sys.argv[0]} --all cidrs.txt 80 443")
        print(f"  Parallel:    sudo {sys.argv[0]} --workers 8 --all cidrs.txt 80 443")
        print(f"  File format: One CIDR block per line (e.g., '192.168.1.0/24')")
        print(f"")
        print(f"Options:")
        print(f"  --all, -a         Scan all IPs in each CIDR block (instead of random)")
        print(f"  --workers, -w N   Number of parallel workers (default: 4)")
        sys.exit(1)

    target_or_file = args[0]
    start          = int(args[1])
    end            = int(args[2])
    timeout        = float(args[3]) if len(args) == 4 else 0.15

    print(f"Configuration: max_workers={max_workers}, scan_all={scan_all}, timeout={timeout}s")

    # Check if first argument is a file or an IP address
    if target_or_file.endswith('.txt') or '/' in target_or_file:
        # Assume it's either a file or a CIDR block
        try:
            # First try to parse as CIDR block
            ipaddress.ip_network(target_or_file, strict=False)
            # If successful, treat as single CIDR block
            print(f"Treating '{target_or_file}' as single CIDR block")
            scan_single_cidr(target_or_file, start, end, timeout, scan_all, max_workers)
        except ValueError:
            # Not a valid CIDR, assume it's a file
            print(f"Treating '{target_or_file}' as CIDR file")
            scan_from_cidr_file(target_or_file, start, end, timeout, scan_all, max_workers)
    else:
        # Assume it's a single IP address
        mode_text = f", timeout={timeout}s"
        print(f"Scanning single target {target_or_file}, ports {start}–{end}{mode_text}…")
        scan_udp_closed(target_or_file, start, end, timeout)