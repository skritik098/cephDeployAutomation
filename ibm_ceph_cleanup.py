#!/usr/bin/env python3
"""
IBM Storage Ceph Cluster Cleanup Script
========================================
Completely removes IBM Storage Ceph cluster and all dependent resources.

This script will:
- Use cephadm rm-cluster to properly remove all daemons and zap OSDs
- Remove Ceph configuration and data directories
- Remove Ceph packages
- Verify ports are freed

WARNING: This is a destructive operation. All data will be lost!

Author: Automated cleanup tool
"""

import argparse
import subprocess
import sys
import os
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock


# Ceph-related ports to verify
CEPH_PORTS = [
    3300,   # Ceph Monitor (v2)
    6789,   # Ceph Monitor (v1)
    8443,   # Dashboard
    9283,   # Prometheus (Ceph)
    3000,   # Grafana
    9093,   # Alertmanager
    9100,   # Node exporter
]

# Packages to remove (minimal set)
CEPH_PACKAGES = [
    "cephadm",
    "ceph-common",
    "ibm-storage-ceph-license",
]

# Directories to clean up (in case rm-cluster misses anything)
CEPH_DIRECTORIES = [
    "/etc/ceph",
    "/var/lib/ceph",
    "/var/log/ceph",
    "/run/ceph",
    "/usr/share/ibm-storage-ceph-license",
]

# Lock for thread-safe printing
print_lock = Lock()


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Print script banner."""
    banner = f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║         IBM Storage Ceph Cluster Cleanup Tool                    ║
║                                                                  ║
║  ⚠️  WARNING: This will DESTROY all Ceph data!                   ║
║                                                                  ║
║  This script removes:                                            ║
║  • All Ceph daemons (MON, MGR, OSD, RGW, MDS)                    ║
║  • Monitoring stack (Prometheus, Grafana, Alertmanager)          ║
║  • All Ceph data and configuration                               ║
║  • Ceph packages                                                 ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def log_info(message: str, host: str = None):
    """Print info message (thread-safe)."""
    with print_lock:
        prefix = f"[{host}] " if host else ""
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} {prefix}{message}")


def log_warn(message: str, host: str = None):
    """Print warning message (thread-safe)."""
    with print_lock:
        prefix = f"[{host}] " if host else ""
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {prefix}{message}")


def log_error(message: str, host: str = None):
    """Print error message (thread-safe)."""
    with print_lock:
        prefix = f"[{host}] " if host else ""
        print(f"{Colors.RED}[ERROR]{Colors.RESET} {prefix}{message}")


def log_step(step: int, total: int, message: str):
    """Print step progress."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}[Step {step}/{total}]{Colors.RESET} {Colors.CYAN}{message}{Colors.RESET}")
    print("=" * 60)


def run_command(cmd: str, host: str = None, check: bool = False, 
                capture_output: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    """
    Run a command locally or on a remote host via SSH.
    """
    if host:
        full_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{host} '{cmd}'"
    else:
        full_cmd = cmd
    
    try:
        result = subprocess.run(
            full_cmd,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        return result
    except subprocess.TimeoutExpired:
        log_warn(f"Command timed out: {cmd[:50]}...", host)
        return subprocess.CompletedProcess(full_cmd, 1, "", "Timeout")
    except Exception as e:
        return subprocess.CompletedProcess(full_cmd, 1, "", str(e))


def run_command_streaming(cmd: str, host: str = None, timeout: int = 600) -> tuple[int, str]:
    """
    Run a command with real-time streaming output while also capturing it.
    
    Args:
        cmd: Command to execute
        host: Remote hostname (None for local execution)
        timeout: Command timeout in seconds
    
    Returns:
        Tuple of (return_code, captured_output)
    """
    if host:
        full_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{host} '{cmd}'"
    else:
        full_cmd = cmd
    
    captured_output = []
    
    try:
        # Use Popen for streaming output
        process = subprocess.Popen(
            full_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            text=True,
            bufsize=1,  # Line buffered
        )
        
        start_time = time.time()
        
        # Read and print output line by line
        while True:
            # Check timeout
            if time.time() - start_time > timeout:
                process.kill()
                raise subprocess.TimeoutExpired(full_cmd, timeout)
            
            line = process.stdout.readline()
            if line:
                with print_lock:
                    print(f"    {line}", end='')
                captured_output.append(line)
            elif process.poll() is not None:
                # Process finished, read any remaining output
                remaining = process.stdout.read()
                if remaining:
                    with print_lock:
                        print(f"    {remaining}", end='')
                    captured_output.append(remaining)
                break
        
        return_code = process.returncode
        output_str = ''.join(captured_output)
        
        return (return_code, output_str)
        
    except subprocess.TimeoutExpired:
        log_error(f"Command timed out after {timeout}s")
        raise
    except Exception as e:
        log_error(f"Command execution failed: {e}")
        raise


def parse_inventory(inventory_path: str) -> list[str]:
    """
    Parse hosts inventory file.
    Returns list of hostnames.
    """
    hosts = []
    path = Path(inventory_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {inventory_path}")
    
    content = path.read_text().strip()
    
    # Try JSON format
    if content.startswith('['):
        try:
            data = json.loads(content)
            for item in data:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    hosts.append(item.get('hostname', item.get('host')))
            return hosts
        except json.JSONDecodeError:
            pass
    
    # Parse line-by-line format
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        hosts.append(parts[0].strip())
    
    return hosts


def get_cluster_fsid(hosts: list[str]) -> str:
    """
    Get the cluster FSID from any host in the cluster.
    
    Args:
        hosts: List of hostnames to try
    
    Returns:
        FSID string or None if not found
    """
    log_info("Detecting cluster FSID...")
    
    for host in hosts:
        # Try multiple methods to get FSID
        
        # Method 1: From cephadm ls output
        result = run_command(
            "cephadm ls 2>/dev/null | grep -oP '\"fsid\": \"\\K[^\"]+' | head -1",
            host=host
        )
        fsid = result.stdout.strip()
        if fsid and len(fsid) == 36:  # Valid UUID format
            log_info(f"  Found FSID from cephadm: {fsid}")
            return fsid
        
        # Method 2: From /var/lib/ceph directory
        result = run_command(
            "ls -1 /var/lib/ceph 2>/dev/null | grep -E '^[a-f0-9-]{36}$' | head -1",
            host=host
        )
        fsid = result.stdout.strip()
        if fsid and len(fsid) == 36:
            log_info(f"  Found FSID from /var/lib/ceph: {fsid}")
            return fsid
        
        # Method 3: From ceph.conf
        result = run_command(
            "grep -oP 'fsid\\s*=\\s*\\K[a-f0-9-]+' /etc/ceph/ceph.conf 2>/dev/null | head -1",
            host=host
        )
        fsid = result.stdout.strip()
        if fsid and len(fsid) == 36:
            log_info(f"  Found FSID from ceph.conf: {fsid}")
            return fsid
        
        # Method 4: Try ceph fsid command via cephadm shell
        result = run_command(
            "cephadm shell -- ceph fsid 2>/dev/null",
            host=host,
            timeout=30
        )
        fsid = result.stdout.strip()
        if fsid and len(fsid) == 36:
            log_info(f"  Found FSID from ceph fsid: {fsid}")
            return fsid
    
    log_warn("  Could not determine cluster FSID")
    return None


def disable_cephadm_module(host: str, fsid: str) -> bool:
    """
    Disable the cephadm orchestrator module before cleanup.
    This prevents new operations while cleanup is in progress.
    
    Args:
        host: Host to run command on (should be one with working ceph)
        fsid: Cluster FSID
    
    Returns:
        True if successful, False otherwise
    """
    log_info("Disabling cephadm orchestrator module...")
    
    result = run_command(
        f"cephadm shell --fsid {fsid} -- ceph mgr module disable cephadm 2>/dev/null || true",
        host=host,
        timeout=60
    )
    
    if result.returncode == 0:
        log_info("  ✓ cephadm module disabled")
        return True
    else:
        log_warn("  Could not disable cephadm module (cluster may already be down)")
        return False


def cleanup_remaining_artifacts(host: str):
    """
    Clean up any remaining artifacts that cephadm rm-cluster might have missed.
    
    Args:
        host: Hostname to cleanup
    """
    log_info(f"Cleaning up remaining artifacts...")
    
    # Remove any orphaned containers
    run_command(
        "podman ps -aq --filter 'name=ceph' | xargs -r podman rm -f 2>/dev/null || true",
        host=host
    )
    
    # Remove ceph directories (in case rm-cluster missed any)
    for directory in CEPH_DIRECTORIES:
        run_command(f"rm -rf {directory} 2>/dev/null || true", host=host)
    
    # Clean up any tmp cephadm files
    run_command("rm -rf /tmp/cephadm-* 2>/dev/null || true", host=host)
    
    # Remove IBM repo file
    run_command("rm -f /etc/yum.repos.d/ibm-storage-ceph*.repo 2>/dev/null || true", host=host)
    
    log_info(f"✓ Artifact cleanup completed")


def remove_packages(host: str) -> bool:
    """
    Remove Ceph packages from a host with streaming output.
    
    Args:
        host: Hostname to remove packages from
    
    Returns:
        True if successful, False otherwise
    """
    log_info(f"Checking installed packages...")
    
    # Check which packages are installed
    installed_packages = []
    for pkg in CEPH_PACKAGES:
        result = run_command(f"rpm -q {pkg} 2>/dev/null", host=host)
        if result.returncode == 0:
            installed_packages.append(pkg)
    
    if not installed_packages:
        log_info(f"No Ceph packages installed")
        return True
    
    log_info(f"Removing packages: {', '.join(installed_packages)}")
    
    pkg_list = " ".join(installed_packages)
    
    try:
        return_code, output = run_command_streaming(
            f"dnf remove -y {pkg_list}",
            host=host,
            timeout=300
        )
        
        if return_code == 0:
            log_info(f"✓ Packages removed")
            return True
        else:
            log_error(f"Package removal failed")
            return False
    
    except Exception as e:
        log_error(f"Package removal failed: {e}")
        return False


def verify_ports_freed(host: str) -> list[int]:
    """Verify Ceph ports are no longer in use."""
    log_info(f"Verifying ports are freed...")
    
    ports_in_use = []
    
    # Check specific Ceph ports
    for port in CEPH_PORTS:
        result = run_command(
            f"ss -tlnp 2>/dev/null | grep ':{port} ' | grep -v grep || true",
            host=host
        )
        if result.stdout.strip():
            ports_in_use.append(port)
            log_warn(f"Port {port} still in use")
    
    # Check sample of OSD port range
    for port in [6800, 6850, 6900, 7000, 7100, 7200]:
        result = run_command(
            f"ss -tlnp 2>/dev/null | grep ':{port} ' | grep -v grep || true",
            host=host
        )
        if result.stdout.strip():
            ports_in_use.append(port)
            log_warn(f"Port {port} still in use")
    
    if not ports_in_use:
        log_info(f"✓ All Ceph ports are freed")
    
    return ports_in_use


def cleanup_host(host: str, fsid: str, skip_packages: bool = False, 
                 skip_zap: bool = False) -> dict:
    """
    Perform complete cleanup on a single host.
    
    Args:
        host: Hostname to cleanup
        fsid: Cluster FSID
        skip_packages: Skip package removal
        skip_zap: Skip OSD zapping (pass to rm-cluster without --zap-osds)
    
    Returns:
        Dictionary with cleanup status
    """
    result = {
        'host': host,
        'success': True,
        'errors': [],
        'ports_in_use': [],
    }
    
    try:
        # Step 1: Run cephadm rm-cluster (REQUIRED - stop if this fails)
        if not fsid:
            log_error(f"No FSID available, cannot proceed with cleanup")
            result['success'] = False
            result['errors'].append("No FSID available - cannot run cephadm rm-cluster")
            return result
        
        if skip_zap:
            cmd = f"cephadm rm-cluster --fsid {fsid} --force"
        else:
            cmd = f"cephadm rm-cluster --fsid {fsid} --zap-osds --force"
        
        log_info(f"Running: {cmd}")
        return_code, output = run_command_streaming(cmd, host=host, timeout=600)
        
        if return_code != 0:
            log_error(f"cephadm rm-cluster failed with code {return_code}")
            result['success'] = False
            result['errors'].append(f"cephadm rm-cluster failed with code {return_code}")
            # Stop here - do not proceed with package removal or directory cleanup
            return result
        
        log_info(f"✓ cephadm rm-cluster completed successfully")
        
        # Step 2: Clean up any remaining artifacts (only if rm-cluster succeeded)
        cleanup_remaining_artifacts(host)
        
        # Step 3: Remove packages (only if rm-cluster succeeded and not skipped)
        if not skip_packages:
            if not remove_packages(host):
                result['errors'].append("Package removal had issues")
                # Don't fail the whole cleanup for package issues
        
        # Step 4: Verify ports
        result['ports_in_use'] = verify_ports_freed(host)
        
    except Exception as e:
        result['success'] = False
        result['errors'].append(str(e))
        log_error(f"Cleanup failed: {e}")
    
    return result


def cleanup_all_hosts(hosts: list[str], fsid: str, skip_packages: bool = False,
                      skip_zap: bool = False) -> dict:
    """
    Run cleanup on all hosts sequentially for clear output tracking.
    
    Args:
        hosts: List of hostnames
        fsid: Cluster FSID
        skip_packages: Skip package removal
        skip_zap: Skip OSD zapping
    
    Returns:
        Dictionary mapping hostname to result
    """
    results = {}
    total_hosts = len(hosts)
    
    for idx, host in enumerate(hosts, 1):
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}[Host {idx}/{total_hosts}] {host}{Colors.RESET}")
        print("-" * 60)
        
        result = cleanup_host(host, fsid, skip_packages, skip_zap)
        results[host] = result
        
        # Print host result immediately
        if result['success']:
            log_info(f"✓ Cleanup completed successfully on {host}")
        else:
            log_error(f"✗ Cleanup failed on {host}")
            for error in result.get('errors', []):
                log_error(f"  {error}")
        
        print("-" * 60)
    
    return results


def print_summary(results: dict):
    """Print cleanup summary."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}CLEANUP SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")
    
    success_count = sum(1 for r in results.values() if r['success'])
    failure_count = len(results) - success_count
    
    for host, result in results.items():
        if result['success']:
            status = f"{Colors.GREEN}✓ SUCCESS{Colors.RESET}"
        else:
            status = f"{Colors.RED}✗ FAILED{Colors.RESET}"
        
        print(f"  {host}: {status}")
        
        if result.get('errors'):
            for error in result['errors']:
                print(f"    {Colors.RED}Error: {error}{Colors.RESET}")
        
        if result.get('ports_in_use'):
            print(f"    {Colors.YELLOW}Ports still in use: {result['ports_in_use']}{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Total: {success_count} succeeded, {failure_count} failed{Colors.RESET}")
    
    if failure_count == 0:
        print(f"\n{Colors.GREEN}Ceph cluster has been completely removed.{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}Some hosts had issues. Please check manually.{Colors.RESET}")


def confirm_cleanup(hosts: list[str], fsid: str) -> bool:
    """Ask user to confirm the cleanup operation."""
    print(f"\n{Colors.RED}{Colors.BOLD}WARNING: This will PERMANENTLY DELETE all Ceph data!{Colors.RESET}")
    
    if fsid:
        print(f"\nCluster FSID: {Colors.CYAN}{fsid}{Colors.RESET}")
    
    print(f"\nHosts to be cleaned:")
    for host in hosts:
        print(f"  • {host}")
    
    print(f"\n{Colors.YELLOW}This action cannot be undone!{Colors.RESET}")
    
    try:
        response = input(f"\nType '{Colors.RED}YES{Colors.RESET}' to confirm cleanup: ")
        return response.strip() == 'YES'
    except (KeyboardInterrupt, EOFError):
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="IBM Storage Ceph Cluster Cleanup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Cleanup all hosts in inventory
  %(prog)s --inventory hosts.txt

  # Cleanup without removing packages (for reinstall)
  %(prog)s --inventory hosts.txt --skip-packages

  # Cleanup without zapping OSDs (keep disk data)
  %(prog)s --inventory hosts.txt --skip-zap

  # Cleanup specific host
  %(prog)s --host ceph-node1

  # Force cleanup without confirmation
  %(prog)s --inventory hosts.txt --force

  # Provide FSID manually if auto-detection fails
  %(prog)s --inventory hosts.txt --fsid a1b2c3d4-e5f6-7890-abcd-ef1234567890
        """
    )
    
    parser.add_argument(
        '--inventory', '-i',
        help='Path to hosts inventory file'
    )
    
    parser.add_argument(
        '--host',
        help='Single host to cleanup (alternative to inventory)'
    )
    
    parser.add_argument(
        '--fsid',
        help='Cluster FSID (auto-detected if not provided)'
    )
    
    parser.add_argument(
        '--skip-packages',
        action='store_true',
        help='Skip package removal (useful for reinstall)'
    )
    
    parser.add_argument(
        '--skip-zap',
        action='store_true',
        help='Skip OSD device zapping (keeps disk data)'
    )
    
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Skip confirmation prompt'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.inventory and not args.host:
        parser.error("Either --inventory or --host is required")
    
    print_banner()
    
    # Get list of hosts
    if args.host:
        hosts = [args.host]
    else:
        hosts = parse_inventory(args.inventory)
    
    if not hosts:
        log_error("No hosts found")
        sys.exit(1)
    
    log_info(f"Hosts to cleanup: {', '.join(hosts)}")
    
    total_steps = 3
    current_step = 0
    
    try:
        # Step 1: Detect or use provided FSID
        current_step += 1
        log_step(current_step, total_steps, "Detecting cluster FSID")
        
        if args.fsid:
            fsid = args.fsid
            log_info(f"Using provided FSID: {fsid}")
        else:
            fsid = get_cluster_fsid(hosts)
        
        if not fsid:
            log_error("Could not detect FSID. Cannot proceed with cleanup.")
            log_info("Please provide FSID manually with --fsid option")
            log_info("You can find the FSID by running: cephadm ls | grep fsid")
            log_info("Or check: ls /var/lib/ceph/")
            sys.exit(1)
        
        # Confirm unless --force
        if not args.force:
            if not confirm_cleanup(hosts, fsid):
                log_info("Cleanup cancelled by user")
                sys.exit(0)
        
        # Step 2: Disable cephadm module (best effort)
        if fsid:
            disable_cephadm_module(hosts[0], fsid)
        
        # Step 3: Run cleanup on all hosts
        current_step += 1
        log_step(current_step, total_steps, "Cleaning up Ceph cluster on all hosts")
        
        results = cleanup_all_hosts(hosts, fsid, args.skip_packages, args.skip_zap)
        
        # Step 4: Print summary
        current_step += 1
        log_step(current_step, total_steps, "Cleanup Summary")
        
        print_summary(results)
        
        # Clean dnf cache on all hosts
        log_info("Cleaning package manager cache...")
        for host in hosts:
            run_command("dnf clean all 2>/dev/null || true", host=host)
        
        # Exit with error if any failures
        if any(not r['success'] for r in results.values()):
            sys.exit(1)
        
    except KeyboardInterrupt:
        log_warn("\nCleanup interrupted by user")
        sys.exit(130)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()