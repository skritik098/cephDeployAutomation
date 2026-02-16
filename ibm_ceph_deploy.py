#!/usr/bin/env python3
"""
IBM Storage Ceph Automated Deployment Script
=============================================
Automates the deployment of IBM Storage Ceph clusters on RHEL-based systems.

Requirements:
    - Python 3.7 or higher
    - SSH access to all target hosts
    - Root privileges on target hosts

Features:
- OS version validation against IBM supported configurations
- Optional SSH passwordless setup for root user
- Repository configuration based on Ceph and OS versions
- IBM Entitled Registry authentication
- Cephadm bootstrap with 3 MONs and MGRs
- Optional OSD deployment using all available devices

Author: Automated deployment tool
"""

import sys

# Check Python version first (before importing modules that may not exist in older Python)
if sys.version_info < (3, 7):
    print("ERROR: Python 3.7 or higher is required.")
    print("Current version: Python {}.{}".format(sys.version_info.major, sys.version_info.minor))
    print("\nOn RHEL 8, install Python 3.9:")
    print("  sudo dnf install python39")
    print("  python3.9 ibm_ceph_deploy.py ...")
    print("\nOn RHEL 9, Python 3.9+ is already available.")
    sys.exit(1)

import argparse
import subprocess
import os
import json
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict
from pathlib import Path


# =============================================================================
# VERSION COMPATIBILITY MATRIX
# =============================================================================
# Based on IBM Storage Ceph documentation
# Simplified to major versions - :latest tag gets the latest release in that stream
# Format: {ceph_major_version: {rhel_major: [supported_minor_versions]}}

VERSION_COMPATIBILITY = {
    "8": {
        "9": ["9.4", "9.5", "9.6"],
    },
    "7": {
        "9": ["9.2", "9.3", "9.4", "9.5", "9.6"],
        "8": ["8.7", "8.8", "8.10"],  # Requires RHEL 9 bootstrap node
    },
    "6": {
        "9": ["9.2", "9.3", "9.4", "9.5"],
        "8": ["8.8", "8.9", "8.10"],  # Requires RHEL 9 bootstrap node
    },
    "5": {
        "9": ["9.0", "9.1", "9.2"],
        "8": ["8.6", "8.7", "8.8"],
    },
}

# Versions that require RHEL 9 bootstrap node even for RHEL 8 clusters
RHEL9_BOOTSTRAP_REQUIRED = ["6", "7"]

# Repository URL template
REPO_URL_TEMPLATE = "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-{major}-rhel-{rhel_major}.repo"

# IBM Container Registry
IBM_REGISTRY_URL = "cp.icr.io/cp"
IBM_REGISTRY_USERNAME = "cp"

# Container image mapping for each IBM Storage Ceph major version
# Image pattern: cp.icr.io/cp/ibm-ceph/ceph-{major}-rhel{rhel_major}:latest
# Using :latest tag pulls the most recent release in that major version stream
# Note: Ceph 5 only has RHEL 8 based images available
CONTAINER_IMAGES = {
    "8": {
        "9": "cp.icr.io/cp/ibm-ceph/ceph-8-rhel9",
    },
    "7": {
        "9": "cp.icr.io/cp/ibm-ceph/ceph-7-rhel9",
        "8": "cp.icr.io/cp/ibm-ceph/ceph-7-rhel8",
    },
    "6": {
        "9": "cp.icr.io/cp/ibm-ceph/ceph-6-rhel9",
        "8": "cp.icr.io/cp/ibm-ceph/ceph-6-rhel8",
    },
    "5": {
        # Ceph 5 only has RHEL 8 based images - use rhel8 image regardless of host OS
        "9": "cp.icr.io/cp/ibm-ceph/ceph-5-rhel8",
        "8": "cp.icr.io/cp/ibm-ceph/ceph-5-rhel8",
    },
}


@dataclass
class HostInfo:
    """Represents a host in the cluster."""
    hostname: str
    ip_address: Optional[str] = None
    is_bootstrap: bool = False
    is_client: bool = False  # Client-only node (gets ceph-common, not full cluster membership)
    os_version: Optional[str] = None


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
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║           IBM Storage Ceph Automated Deployment Tool             ║
║                                                                  ║
║  Deploys IBM Storage Ceph clusters with:                         ║
║  • 3 MONs & MGRs (high availability)                             ║
║  • Dashboard & Monitoring Stack                                  ║
║  • Optional OSD deployment on all available devices              ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def log_info(message: str):
    """Print info message."""
    print(f"{Colors.GREEN}[INFO]{Colors.RESET} {message}")


def log_warn(message: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {message}")


def log_error(message: str):
    """Print error message."""
    print(f"{Colors.RED}[ERROR]{Colors.RESET} {message}")


def log_step(step: int, total: int, message: str):
    """Print step progress."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}[Step {step}/{total}]{Colors.RESET} {Colors.CYAN}{message}{Colors.RESET}")
    print("=" * 60)


def run_command(cmd: str, host: Optional[str] = None, check: bool = True, 
                capture_output: bool = False, timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Run a command locally or on a remote host via SSH.
    
    Args:
        cmd: Command to execute
        host: Remote hostname (None for local execution)
        check: Raise exception on non-zero exit
        capture_output: Capture stdout/stderr
        timeout: Command timeout in seconds
    
    Returns:
        CompletedProcess instance
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
    except subprocess.CalledProcessError as e:
        if capture_output:
            log_error(f"Command failed: {cmd}")
            if e.stdout:
                print(f"STDOUT: {e.stdout}")
            if e.stderr:
                print(f"STDERR: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        log_error(f"Command timed out after {timeout}s: {cmd}")
        raise


def run_command_streaming(cmd: str, host: Optional[str] = None, timeout: int = 900) -> Tuple[int, str]:
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
                print(f"    {line}", end='')  # Print with indent
                captured_output.append(line)
            elif process.poll() is not None:
                # Process finished, read any remaining output
                remaining = process.stdout.read()
                if remaining:
                    print(f"    {remaining}", end='')
                    captured_output.append(remaining)
                break
        
        return_code = process.returncode
        output_str = ''.join(captured_output)
        
        return (return_code, output_str)
        
    except subprocess.TimeoutExpired:
        log_error(f"Command timed out after {timeout}s: {cmd}")
        raise
    except Exception as e:
        log_error(f"Command execution failed: {e}")
        raise


def get_os_version(host: Optional[str] = None) -> str:
    """
    Get RHEL version from a host.
    
    Returns:
        Version string like "9.4" or "8.10"
    """
    try:
        result = run_command(
            "cat /etc/redhat-release",
            host=host,
            capture_output=True
        )
        release_info = result.stdout.strip()
        
        # Extract version number (e.g., "9.4" from "Red Hat Enterprise Linux release 9.4 (Plow)")
        match = re.search(r'release\s+(\d+\.\d+)', release_info)
        if match:
            return match.group(1)
        
        # Fallback: try /etc/os-release
        result = run_command(
            "grep VERSION_ID /etc/os-release | cut -d'\"' -f2",
            host=host,
            capture_output=True
        )
        return result.stdout.strip()
    except Exception as e:
        log_error(f"Failed to get OS version from {host or 'localhost'}: {e}")
        raise


def get_host_ip(host: str) -> str:
    """Get the primary IP address of a host."""
    try:
        # Get all IPs and parse in Python to avoid shell quoting issues with SSH
        result = run_command(
            "hostname -I",
            host=host,
            capture_output=True
        )
        output = result.stdout.strip()
        if output:
            # Take the first IP address
            ip = output.split()[0]
            return ip
        
        # Fallback: resolve hostname using getent
        result = run_command(
            f"getent hosts {host}",
            capture_output=True
        )
        output = result.stdout.strip()
        if output:
            # getent output format: "IP_ADDRESS hostname"
            ip = output.split()[0]
            return ip
        
        return host
    except Exception:
        log_warn(f"Could not determine IP for {host}, using hostname")
        return host


def validate_os_compatibility(ceph_version: str, os_version: str, is_bootstrap: bool = False, 
                              force: bool = False) -> Tuple[bool, bool]:
    """
    Validate if the OS version is compatible with the Ceph version.
    
    Args:
        ceph_version: IBM Storage Ceph major version (e.g., "7")
        os_version: RHEL version (e.g., "9.4")
        is_bootstrap: Whether this is the bootstrap node
        force: If True, continue with warning instead of failing
    
    Returns:
        Tuple of (is_compatible: bool, is_warning: bool)
        - is_compatible: True if compatible or force=True
        - is_warning: True if compatibility issue was bypassed with force
    """
    if ceph_version not in VERSION_COMPATIBILITY:
        log_error(f"Unknown Ceph version: {ceph_version}")
        log_info(f"Supported versions: {', '.join(VERSION_COMPATIBILITY.keys())}")
        return (False, False)
    
    rhel_major = os_version.split('.')[0]
    compat = VERSION_COMPATIBILITY[ceph_version]
    
    # Check if RHEL major version is supported
    if rhel_major not in compat:
        msg = f"RHEL {rhel_major} is not supported for IBM Storage Ceph {ceph_version}"
        supported = [f"RHEL {k}" for k in compat.keys()]
        
        if force:
            log_warn(f"{msg} (continuing with --force)")
            log_info(f"Supported OS versions: {', '.join(supported)}")
            return (True, True)
        else:
            log_error(msg)
            log_info(f"Supported OS versions: {', '.join(supported)}")
            log_info("Use --force to continue anyway (not recommended)")
            return (False, False)
    
    # Check specific minor version
    if os_version not in compat[rhel_major]:
        msg = f"RHEL {os_version} is not in the supported list for IBM Storage Ceph {ceph_version}"
        
        if force:
            log_warn(f"{msg} (continuing with --force)")
            log_info(f"Supported RHEL {rhel_major} versions: {', '.join(compat[rhel_major])}")
            return (True, True)
        else:
            log_error(msg)
            log_info(f"Supported RHEL {rhel_major} versions: {', '.join(compat[rhel_major])}")
            log_info("Use --force to continue anyway (not recommended)")
            return (False, False)
    
    # Check bootstrap node requirement for RHEL 8 clusters
    if rhel_major == "8" and ceph_version in RHEL9_BOOTSTRAP_REQUIRED:
        if is_bootstrap:
            msg = f"IBM Storage Ceph {ceph_version} requires RHEL 9 for the bootstrap node"
            if force:
                log_warn(f"{msg} (continuing with --force)")
                log_info("RHEL 8 bootstrap is not officially supported and may fail")
                return (True, True)
            else:
                log_error(msg)
                log_info("RHEL 8 nodes can only be added after bootstrapping from a RHEL 9 node")
                log_info("Use --force to continue anyway (not recommended)")
                return (False, False)
        else:
            log_warn(f"RHEL 8 node detected - ensure bootstrap node is RHEL 9")
    
    return (True, False)


def get_container_image(ceph_version: str, rhel_major: str) -> str:
    """
    Get the container image for a specific Ceph major version and RHEL version.
    
    Args:
        ceph_version: IBM Storage Ceph major version (e.g., "7")
        rhel_major: RHEL major version (e.g., "9")
    
    Returns:
        Full container image path with :latest tag
    """
    if ceph_version not in CONTAINER_IMAGES:
        raise ValueError(f"No container image defined for Ceph version {ceph_version}")
    
    version_images = CONTAINER_IMAGES[ceph_version]
    
    if rhel_major not in version_images:
        raise ValueError(f"No container image for Ceph {ceph_version} on RHEL {rhel_major}")
    
    # Return image with :latest tag
    return f"{version_images[rhel_major]}:latest"


def parse_inventory(inventory_path: str) -> Tuple[List[HostInfo], List[HostInfo]]:
    """
    Parse hosts inventory file.
    
    Supported formats:
    - Simple: one hostname per line
    - With IP: hostname,ip_address per line
    - With role: hostname,ip_address,client per line (client nodes)
    - JSON: [{"hostname": "...", "ip": "...", "role": "client"}, ...]
    
    First non-client host is assumed to be the bootstrap node.
    
    Returns:
        Tuple of (cluster_hosts, client_hosts)
    """
    cluster_hosts = []
    client_hosts = []
    path = Path(inventory_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {inventory_path}")
    
    content = path.read_text().strip()
    
    # Try JSON format first
    if content.startswith('['):
        try:
            data = json.loads(content)
            first_cluster_host = True
            for item in data:
                if isinstance(item, str):
                    cluster_hosts.append(HostInfo(hostname=item, is_bootstrap=first_cluster_host))
                    first_cluster_host = False
                elif isinstance(item, dict):
                    role = item.get('role', '').lower()
                    host = HostInfo(
                        hostname=item.get('hostname', item.get('host')),
                        ip_address=item.get('ip', item.get('ip_address')),
                        is_client=(role == 'client'),
                    )
                    if host.is_client:
                        client_hosts.append(host)
                    else:
                        host.is_bootstrap = first_cluster_host
                        first_cluster_host = False
                        cluster_hosts.append(host)
            return (cluster_hosts, client_hosts)
        except json.JSONDecodeError:
            pass
    
    # Parse line-by-line format
    first_cluster_host = True
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        parts = [p.strip() for p in line.split(',')]
        hostname = parts[0]
        ip_address = parts[1] if len(parts) > 1 and parts[1] and not parts[1].lower() == 'client' else None
        
        # Check if this is a client node
        is_client = False
        for part in parts[1:]:
            if part.lower() == 'client':
                is_client = True
                break
        
        host = HostInfo(
            hostname=hostname,
            ip_address=ip_address,
            is_client=is_client,
        )
        
        if is_client:
            client_hosts.append(host)
        else:
            host.is_bootstrap = first_cluster_host
            first_cluster_host = False
            cluster_hosts.append(host)
    
    return (cluster_hosts, client_hosts)


def setup_ssh_passwordless(hosts: List[HostInfo], ssh_password: str):
    """
    Configure SSH passwordless authentication for root user.
    
    Args:
        hosts: List of target hosts
        ssh_password: Current root password for initial access
    """
    log_info("Setting up SSH passwordless authentication...")
    
    # Check if sshpass is available
    try:
        run_command("which sshpass", capture_output=True)
    except subprocess.CalledProcessError:
        log_info("Installing sshpass...")
        run_command("dnf install -y sshpass")
    
    # Generate SSH key if not exists
    ssh_key_path = Path.home() / ".ssh" / "id_rsa"
    if not ssh_key_path.exists():
        log_info("Generating SSH key pair...")
        run_command(f'ssh-keygen -t rsa -b 4096 -f {ssh_key_path} -N ""')
    
    # Copy SSH key to all hosts
    for host in hosts:
        log_info(f"Copying SSH key to {host.hostname}...")
        try:
            run_command(
                f'sshpass -p "{ssh_password}" ssh-copy-id -o StrictHostKeyChecking=no root@{host.hostname}',
                check=True
            )
            log_info(f"  ✓ SSH key copied to {host.hostname}")
        except subprocess.CalledProcessError:
            log_error(f"  ✗ Failed to copy SSH key to {host.hostname}")
            raise


def configure_repositories(host: str, ceph_version: str, rhel_major: str) -> bool:
    """
    Configure IBM Storage Ceph repositories on a host.
    
    Args:
        host: Target hostname
        ceph_version: Ceph major version (e.g., "7")
        rhel_major: RHEL major version (e.g., "9")
    
    Returns:
        True if configuration was performed, False if skipped (already configured)
    """
    log_info(f"Checking repositories on {host}...")
    
    # Check if IBM Ceph repo already exists
    try:
        result = run_command(
            "ls /etc/yum.repos.d/ibm-storage-ceph*.repo 2>/dev/null | head -1",
            host=host,
            capture_output=True,
            check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            # Verify the repo is for the correct version
            check_result = run_command(
                f"grep -l 'ibm-storage-ceph-{ceph_version}' /etc/yum.repos.d/ibm-storage-ceph*.repo 2>/dev/null",
                host=host,
                capture_output=True,
                check=False
            )
            if check_result.returncode == 0 and check_result.stdout.strip():
                log_info(f"  ⏭ Repository already configured on {host}, skipping")
                return False
    except Exception:
        pass
    
    log_info(f"  Configuring repositories on {host}...")
    
    # Repository URL (ceph_version is already the major version)
    repo_url = REPO_URL_TEMPLATE.format(major=ceph_version, rhel_major=rhel_major)
    
    commands = [
        # Enable required RHEL repos (assuming system is already registered)
        f"subscription-manager repos --enable=rhel-{rhel_major}-for-x86_64-baseos-rpms 2>/dev/null || true",
        f"subscription-manager repos --enable=rhel-{rhel_major}-for-x86_64-appstream-rpms 2>/dev/null || true",
        
        # Download and install IBM Ceph repo
        f"curl -s {repo_url} -o /etc/yum.repos.d/ibm-storage-ceph.repo",
        
        # Clean and update cache
        "dnf clean all",
        "dnf makecache",
    ]
    
    for cmd in commands:
        run_command(cmd, host=host)
    
    log_info(f"  ✓ Repositories configured on {host}")
    return True


def install_packages(host: str, is_bootstrap: bool = False) -> bool:
    """
    Install required packages on a host.
    
    IMPORTANT: ibm-storage-ceph-license must be installed and accepted BEFORE
    cephadm can be installed. The sequence is:
    1. Install ibm-storage-ceph-license
    2. Accept the license agreement
    3. Install remaining packages (including cephadm on bootstrap)
    
    Args:
        host: Target hostname
        is_bootstrap: Whether this is the bootstrap node
    
    Returns:
        True if installation was performed, False if skipped (already installed)
    """
    log_info(f"Checking packages on {host}...")
    
    # Check if license package is installed
    license_result = run_command(
        "rpm -q ibm-storage-ceph-license &>/dev/null && echo 'installed' || echo 'missing'",
        host=host,
        capture_output=True,
        check=False
    )
    license_installed = "installed" in license_result.stdout
    
    # Step 1: Install and accept license first (required before cephadm)
    if not license_installed:
        log_info(f"  Installing ibm-storage-ceph-license on {host}...")
        run_command("dnf install -y ibm-storage-ceph-license", host=host, timeout=300)
    
    # Step 2: Accept IBM license (must be done before installing cephadm)
    log_info(f"  Accepting IBM license agreement on {host}...")
    run_command(
        "mkdir -p /usr/share/ibm-storage-ceph-license && "
        "touch /usr/share/ibm-storage-ceph-license/accept",
        host=host
    )
    
    # Step 3: Define remaining packages to install
    packages = [
        "podman",
        "lvm2",
        "chrony",
    ]
    
    # Bootstrap node gets cephadm (can only be installed after license is accepted)
    if is_bootstrap:
        packages.append("cephadm")
    
    # Check which packages are missing
    missing_packages = []
    for pkg in packages:
        result = run_command(
            f"rpm -q {pkg} &>/dev/null && echo 'installed' || echo 'missing'",
            host=host,
            capture_output=True,
            check=False
        )
        if "missing" in result.stdout:
            missing_packages.append(pkg)
    
    if not missing_packages and license_installed:
        log_info(f"  ⏭ All packages already installed on {host}, skipping")
        # Still ensure chronyd is running
        run_command("systemctl enable --now chronyd 2>/dev/null || true", host=host)
        return False
    
    # Step 4: Install remaining packages
    if missing_packages:
        log_info(f"  Installing packages on {host}: {', '.join(missing_packages)}")
        pkg_list = " ".join(missing_packages)
        run_command(f"dnf install -y {pkg_list}", host=host, timeout=600)
    
    # Enable and start chronyd for time sync
    run_command("systemctl enable --now chronyd", host=host)
    
    log_info(f"  ✓ Packages installed on {host}")
    return True


def install_client_packages(host: str) -> bool:
    """
    Install ceph-common package on a client node.
    
    IMPORTANT: ibm-storage-ceph-license must be installed and accepted BEFORE
    ceph-common can be installed.
    
    Args:
        host: Target hostname
    
    Returns:
        True if installation was performed, False if skipped (already installed)
    """
    log_info(f"Checking client packages on {host}...")
    
    # Check if license is installed
    license_result = run_command(
        "rpm -q ibm-storage-ceph-license &>/dev/null && echo 'installed' || echo 'missing'",
        host=host,
        capture_output=True,
        check=False
    )
    license_installed = "installed" in license_result.stdout
    
    # Check if ceph-common is already installed
    ceph_result = run_command(
        "rpm -q ceph-common &>/dev/null && echo 'installed' || echo 'missing'",
        host=host,
        capture_output=True,
        check=False
    )
    ceph_installed = "installed" in ceph_result.stdout
    
    if license_installed and ceph_installed:
        log_info(f"  ⏭ Client packages already installed on {host}, skipping")
        return False
    
    # Step 1: Install and accept license first (required before ceph-common)
    if not license_installed:
        log_info(f"  Installing ibm-storage-ceph-license on {host}...")
        run_command("dnf install -y ibm-storage-ceph-license", host=host, timeout=300)
    
    # Step 2: Accept IBM license
    run_command(
        "mkdir -p /usr/share/ibm-storage-ceph-license && "
        "touch /usr/share/ibm-storage-ceph-license/accept",
        host=host
    )
    
    # Step 3: Install ceph-common
    if not ceph_installed:
        log_info(f"  Installing ceph-common on {host}...")
        run_command("dnf install -y ceph-common", host=host, timeout=300)
    
    log_info(f"  ✓ Client packages installed on {host}")
    return True


def setup_client_nodes(bootstrap_host: str, client_hosts: List[HostInfo]):
    """
    Set up client nodes with ceph-common and distribute cluster config.
    
    Args:
        bootstrap_host: Bootstrap node hostname
        client_hosts: List of client hosts
    """
    if not client_hosts:
        return
    
    log_info(f"Setting up {len(client_hosts)} client nodes...")
    
    # First, install ceph-common on all client nodes in parallel
    log_info("  Installing ceph-common on client nodes...")
    
    results = {}
    with ThreadPoolExecutor(max_workers=min(5, len(client_hosts))) as executor:
        future_to_host = {executor.submit(install_client_packages, h.hostname): h for h in client_hosts}
        
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                results[host.hostname] = (True, result)
            except Exception as e:
                results[host.hostname] = (False, e)
                log_error(f"  ✗ Client setup failed on {host.hostname}: {e}")
    
    # Check for failures
    failures = [h for h, (success, _) in results.items() if not success]
    if failures:
        log_warn(f"  Client package installation failed on: {', '.join(failures)}")
    
    # Distribute ceph.conf and keyring to client nodes
    log_info("  Distributing cluster configuration to clients...")
    
    for client in client_hosts:
        if client.hostname in failures:
            continue
        
        try:
            # Create /etc/ceph directory on client
            run_command("mkdir -p /etc/ceph", host=client.hostname)
            
            # Copy ceph.conf from bootstrap node to client
            run_command(
                f"scp -o StrictHostKeyChecking=no /etc/ceph/ceph.conf root@{client.hostname}:/etc/ceph/",
                host=bootstrap_host
            )
            
            # Copy client keyring (read-only access)
            # First check if a client keyring exists, otherwise create one
            run_command(
                "cephadm shell -- ceph auth get-or-create client.admin -o /etc/ceph/ceph.client.admin.keyring 2>/dev/null || true",
                host=bootstrap_host
            )
            run_command(
                f"scp -o StrictHostKeyChecking=no /etc/ceph/ceph.client.admin.keyring root@{client.hostname}:/etc/ceph/",
                host=bootstrap_host
            )
            
            log_info(f"  ✓ Client {client.hostname} configured")
        except Exception as e:
            log_error(f"  ✗ Failed to configure client {client.hostname}: {e}")
    
    log_info("  ✓ Client nodes setup completed")


def configure_firewall(host: str):
    """Configure firewall rules for Ceph services."""
    log_info(f"Configuring firewall on {host}...")
    
    # Ceph ports
    ports = [
        "3300/tcp",   # Ceph Monitor (v2)
        "6789/tcp",   # Ceph Monitor (v1)
        "6800-7300/tcp",  # OSDs
        "8443/tcp",   # Dashboard
        "9283/tcp",   # Prometheus
        "3000/tcp",   # Grafana
        "9093/tcp",   # Alertmanager
        "9100/tcp",   # Node exporter
    ]
    
    for port in ports:
        run_command(f"firewall-cmd --permanent --add-port={port} 2>/dev/null || true", host=host)
    
    run_command("firewall-cmd --reload 2>/dev/null || true", host=host)
    log_info(f"  ✓ Firewall configured on {host}")


def registry_login(host: str, entitlement_key: str):
    """
    Authenticate to IBM Entitled Registry.
    
    Args:
        host: Target hostname
        entitlement_key: IBM entitlement key
    """
    log_info(f"Logging into IBM registry on {host}...")
    
    run_command(
        f'podman login {IBM_REGISTRY_URL} -u {IBM_REGISTRY_USERNAME} -p "{entitlement_key}"',
        host=host
    )
    
    log_info(f"  ✓ Registry login successful on {host}")


def run_parallel_on_hosts(func, hosts: List[HostInfo], *args, max_workers: int = 5, **kwargs) -> dict:
    """
    Run a function in parallel across multiple hosts.
    
    Args:
        func: Function to execute (must accept host as first parameter)
        hosts: List of HostInfo objects
        *args: Additional positional arguments for func
        max_workers: Maximum number of parallel workers
        **kwargs: Additional keyword arguments for func
    
    Returns:
        Dictionary mapping hostname to (success: bool, result/exception)
    """
    results = {}
    
    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as executor:
        # Submit all tasks
        future_to_host = {}
        for host in hosts:
            future = executor.submit(func, host.hostname, *args, **kwargs)
            future_to_host[future] = host
        
        # Collect results as they complete
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                results[host.hostname] = (True, result)
            except Exception as e:
                results[host.hostname] = (False, e)
                log_error(f"  ✗ Failed on {host.hostname}: {e}")
    
    return results


def configure_repositories_parallel(hosts: List[HostInfo], ceph_version: str):
    """
    Configure repositories on all hosts in parallel.
    
    Args:
        hosts: List of hosts
        ceph_version: Ceph major version
    """
    log_info(f"Configuring repositories on {len(hosts)} hosts in parallel...")
    
    def configure_host(hostname: str):
        # Find the host to get OS version
        host = next(h for h in hosts if h.hostname == hostname)
        rhel_major = host.os_version.split('.')[0]
        return configure_repositories(hostname, ceph_version, rhel_major)
    
    results = {}
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as executor:
        future_to_host = {executor.submit(configure_host, h.hostname): h for h in hosts}
        
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                results[host.hostname] = (True, result)
            except Exception as e:
                results[host.hostname] = (False, e)
                log_error(f"  ✗ Repository configuration failed on {host.hostname}: {e}")
    
    # Check for failures
    failures = [h for h, (success, _) in results.items() if not success]
    if failures:
        raise RuntimeError(f"Repository configuration failed on: {', '.join(failures)}")
    
    configured = sum(1 for _, (_, was_configured) in results.items() if was_configured)
    skipped = len(hosts) - configured
    if skipped > 0:
        log_info(f"  Summary: {configured} configured, {skipped} skipped (already configured)")


def install_packages_parallel(hosts: List[HostInfo], bootstrap_hostname: str):
    """
    Install packages on all hosts in parallel.
    
    Args:
        hosts: List of hosts
        bootstrap_hostname: Hostname of the bootstrap node
    """
    log_info(f"Installing packages on {len(hosts)} hosts in parallel...")
    
    def install_on_host(hostname: str):
        is_bootstrap = (hostname == bootstrap_hostname)
        return install_packages(hostname, is_bootstrap)
    
    results = {}
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as executor:
        future_to_host = {executor.submit(install_on_host, h.hostname): h for h in hosts}
        
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                results[host.hostname] = (True, result)
            except Exception as e:
                results[host.hostname] = (False, e)
                log_error(f"  ✗ Package installation failed on {host.hostname}: {e}")
    
    # Check for failures
    failures = [h for h, (success, _) in results.items() if not success]
    if failures:
        raise RuntimeError(f"Package installation failed on: {', '.join(failures)}")
    
    installed = sum(1 for _, (_, was_installed) in results.items() if was_installed)
    skipped = len(hosts) - installed
    if skipped > 0:
        log_info(f"  Summary: {installed} installed, {skipped} skipped (already installed)")


def configure_firewall_parallel(hosts: List[HostInfo]):
    """
    Configure firewall on all hosts in parallel.
    
    Args:
        hosts: List of hosts
    """
    log_info(f"Configuring firewall on {len(hosts)} hosts in parallel...")
    
    results = {}
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as executor:
        future_to_host = {executor.submit(configure_firewall, h.hostname): h for h in hosts}
        
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                future.result()
                results[host.hostname] = True
            except Exception as e:
                results[host.hostname] = False
                log_error(f"  ✗ Firewall configuration failed on {host.hostname}: {e}")
    
    failures = [h for h, success in results.items() if not success]
    if failures:
        log_warn(f"  Firewall configuration failed on: {', '.join(failures)} (continuing anyway)")


def registry_login_parallel(hosts: List[HostInfo], entitlement_key: str):
    """
    Perform registry login on all hosts in parallel.
    
    Args:
        hosts: List of hosts
        entitlement_key: IBM entitlement key
    """
    log_info(f"Logging into IBM registry on {len(hosts)} hosts in parallel...")
    
    results = {}
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as executor:
        future_to_host = {executor.submit(registry_login, h.hostname, entitlement_key): h for h in hosts}
        
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                future.result()
                results[host.hostname] = True
            except Exception as e:
                results[host.hostname] = False
                log_error(f"  ✗ Registry login failed on {host.hostname}: {e}")
    
    failures = [h for h, success in results.items() if not success]
    if failures:
        raise RuntimeError(f"Registry login failed on: {', '.join(failures)}")


def bootstrap_cluster(bootstrap_host: HostInfo, mon_ip: str, entitlement_key: str,
                      container_image: str, cluster_network: Optional[str] = None) -> dict:
    """
    Bootstrap the Ceph cluster using cephadm.
    
    Args:
        bootstrap_host: Bootstrap node info
        mon_ip: IP address for the first monitor
        entitlement_key: IBM entitlement key
        container_image: Full container image path (e.g., cp.icr.io/cp/ibm-ceph/ceph-7-rhel9:latest)
        cluster_network: Optional cluster network CIDR
    
    Returns:
        Dictionary with bootstrap details including dashboard credentials
    """
    log_info(f"Bootstrapping Ceph cluster on {bootstrap_host.hostname}...")
    log_info(f"  Using container image: {container_image}")
    
    # Build bootstrap command with simple/default options
    # Note: --image must come BEFORE bootstrap subcommand
    bootstrap_cmd = [
        f"cephadm --image {container_image} bootstrap",
        f"--mon-ip {mon_ip}",
        f"--registry-url {IBM_REGISTRY_URL}",
        f"--registry-username {IBM_REGISTRY_USERNAME}",
        f"--registry-password {entitlement_key}",
    ]
    
    # Add cluster network if specified
    if cluster_network:
        bootstrap_cmd.append(f"--cluster-network {cluster_network}")
    
    cmd = " ".join(bootstrap_cmd)
    
    # Run bootstrap with streaming output (this takes several minutes)
    log_info("  This may take 5-10 minutes. Streaming output below:")
    print("  " + "-" * 58)
    
    return_code, output = run_command_streaming(cmd, host=bootstrap_host.hostname, timeout=900)
    
    print("  " + "-" * 58)
    
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, cmd)
    
    log_info("  ✓ Cluster bootstrap completed")
    
    # Parse bootstrap output for credentials
    bootstrap_info = parse_bootstrap_output(output)
    
    return bootstrap_info


def parse_bootstrap_output(output: str) -> dict:
    """
    Parse cephadm bootstrap output to extract dashboard credentials and URLs.
    
    Args:
        output: Raw bootstrap command output
    
    Returns:
        Dictionary with dashboard_url, dashboard_user, dashboard_password, etc.
    """
    info = {
        'dashboard_url': None,
        'dashboard_user': 'admin',
        'dashboard_password': None,
        'raw_output': output,
    }
    
    # Pattern: Ceph Dashboard is now available at:
    #          https://host:8443/
    url_patterns = [
        r'Ceph Dashboard is now available at:\s*\n\s*(https?://[^\s]+)',
        r'dashboard.*available.*?(https?://[^\s]+)',
        r'(https?://[\d\.]+:8443/?)',
    ]
    
    for pattern in url_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            info['dashboard_url'] = match.group(1).strip()
            break
    
    # Pattern: User: admin
    #          Password: <password>
    # Or: password: <password>
    password_patterns = [
        r'[Pp]assword:\s*(\S+)',
        r'password\s+is\s+["\']?(\S+)["\']?',
        r'User:\s*admin\s*\n\s*Password:\s*(\S+)',
    ]
    
    for pattern in password_patterns:
        match = re.search(pattern, output)
        if match:
            password = match.group(1).strip()
            # Clean up any trailing punctuation
            password = password.rstrip('.,;:')
            if password and len(password) > 4:  # Sanity check
                info['dashboard_password'] = password
                break
    
    return info


def distribute_ssh_keys(bootstrap_host: str, target_hosts: List[HostInfo]):
    """
    Distribute Ceph cluster SSH public key to additional hosts.
    
    Args:
        bootstrap_host: Bootstrap node hostname
        target_hosts: List of hosts to receive the key
    """
    log_info("Distributing Ceph SSH keys to cluster nodes...")
    
    for host in target_hosts:
        if host.is_bootstrap:
            continue
        
        log_info(f"  Copying Ceph SSH key to {host.hostname}...")
        run_command(
            f"ssh-copy-id -f -i /etc/ceph/ceph.pub root@{host.hostname}",
            host=bootstrap_host
        )
    
    log_info("  ✓ SSH keys distributed")


def add_hosts_to_cluster(bootstrap_host: str, hosts: List[HostInfo]):
    """
    Add additional hosts to the Ceph cluster.
    
    Args:
        bootstrap_host: Bootstrap node hostname
        hosts: List of hosts to add
    """
    log_info("Adding hosts to the cluster...")
    
    for host in hosts:
        if host.is_bootstrap:
            continue
        
        ip = host.ip_address or get_host_ip(host.hostname)
        log_info(f"  Adding {host.hostname} ({ip})...")
        
        # Add host with mon and osd labels
        run_command(
            f"cephadm shell -- ceph orch host add {host.hostname} {ip} --labels=_admin,mon,osd",
            host=bootstrap_host
        )
    
    # Wait for hosts to be recognized
    log_info("  Waiting for hosts to be recognized...")
    time.sleep(10)
    
    # List hosts
    result = run_command(
        "cephadm shell -- ceph orch host ls",
        host=bootstrap_host,
        capture_output=True
    )
    print(result.stdout)
    
    log_info("  ✓ Hosts added to cluster")


def configure_mon_mgr_placement(bootstrap_host: str, host_count: int):
    """
    Configure MON and MGR placement for HA (3 daemons each if enough hosts).
    
    Args:
        bootstrap_host: Bootstrap node hostname
        host_count: Total number of hosts in cluster
    """
    # Determine daemon count (max 3, or host_count if less)
    daemon_count = min(3, host_count)
    
    log_info(f"Configuring {daemon_count} MONs and MGRs for HA...")
    
    # Apply MON placement
    run_command(
        f"cephadm shell -- ceph orch apply mon {daemon_count}",
        host=bootstrap_host
    )
    
    # Apply MGR placement
    run_command(
        f"cephadm shell -- ceph orch apply mgr {daemon_count}",
        host=bootstrap_host
    )
    
    log_info(f"  ✓ Configured {daemon_count} MONs and {daemon_count} MGRs")


def deploy_osds(bootstrap_host: str):
    """
    Deploy OSDs on all available devices.
    
    Args:
        bootstrap_host: Bootstrap node hostname
    """
    log_info("Deploying OSDs on all available devices...")
    
    # Refresh device inventory multiple times to ensure accurate discovery
    # The --refresh flag doesn't instantly update, it triggers a background refresh
    log_info("  Refreshing device inventory (this takes ~15 seconds)...")
    
    for attempt in range(3):
        run_command(
            "cephadm shell -- ceph orch device ls --refresh",
            host=bootstrap_host,
            capture_output=True
        )
        if attempt < 2:  # Don't sleep after last attempt
            time.sleep(5)
    
    # Wait a bit more for the refresh to fully complete
    time.sleep(3)
    
    # Now list available devices
    log_info("  Discovering available devices...")
    result = run_command(
        "cephadm shell -- ceph orch device ls --wide",
        host=bootstrap_host,
        capture_output=True
    )
    print(result.stdout)
    
    # Apply OSD deployment on all available devices
    log_info("  Applying OSD service...")
    run_command(
        "cephadm shell -- ceph orch apply osd --all-available-devices",
        host=bootstrap_host
    )
    
    log_info("  ✓ OSD deployment initiated (devices will be provisioned automatically)")


def wait_for_cluster_health(bootstrap_host: str, timeout: int = 300):
    """
    Wait for cluster to reach healthy state.
    
    Args:
        bootstrap_host: Bootstrap node hostname
        timeout: Maximum wait time in seconds
    """
    log_info("Waiting for cluster to become healthy...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            result = run_command(
                "cephadm shell -- ceph health",
                host=bootstrap_host,
                capture_output=True
            )
            health = result.stdout.strip()
            
            if "HEALTH_OK" in health:
                log_info("  ✓ Cluster is healthy!")
                return True
            elif "HEALTH_WARN" in health:
                log_warn(f"  Cluster health: {health}")
                # HEALTH_WARN is acceptable for initial deployment
                return True
            
            log_info(f"  Current status: {health}")
        except Exception:
            pass
        
        time.sleep(15)
    
    log_warn("  Cluster did not reach healthy state within timeout")
    return False


def get_cluster_info(bootstrap_host: str, bootstrap_info: Optional[dict] = None) -> dict:
    """
    Gather cluster information for final summary.
    
    Args:
        bootstrap_host: Bootstrap node hostname
        bootstrap_info: Optional dictionary with bootstrap output (contains dashboard creds)
    
    Returns:
        Dictionary with cluster details
    """
    info = {}
    
    # Cluster status
    try:
        result = run_command(
            "cephadm shell -- ceph -s",
            host=bootstrap_host,
            capture_output=True
        )
        info['status'] = result.stdout
    except Exception:
        info['status'] = "Unable to retrieve"
    
    # Dashboard URL and credentials from bootstrap output
    if bootstrap_info:
        info['dashboard_url'] = bootstrap_info.get('dashboard_url')
        info['dashboard_password'] = bootstrap_info.get('dashboard_password')
    
    # If not from bootstrap output, try to get from cluster
    if not info.get('dashboard_url'):
        try:
            result = run_command(
                "cephadm shell -- ceph mgr services",
                host=bootstrap_host,
                capture_output=True
            )
            services = json.loads(result.stdout)
            info['dashboard_url'] = services.get('dashboard', 'N/A')
            info['prometheus_url'] = services.get('prometheus', 'N/A')
        except Exception:
            info['dashboard_url'] = "Unable to retrieve"
            info['prometheus_url'] = "Unable to retrieve"
    else:
        # Still get prometheus URL from services
        try:
            result = run_command(
                "cephadm shell -- ceph mgr services",
                host=bootstrap_host,
                capture_output=True
            )
            services = json.loads(result.stdout)
            info['prometheus_url'] = services.get('prometheus', 'N/A')
        except Exception:
            info['prometheus_url'] = "Unable to retrieve"
    
    # Dashboard password fallback - try reading from file if not parsed from output
    if not info.get('dashboard_password'):
        try:
            result = run_command(
                "cat /etc/ceph/ceph.dashboard.password 2>/dev/null || "
                "cephadm shell -- ceph dashboard ac-user-show admin 2>/dev/null | grep -i password || "
                "echo ''",
                host=bootstrap_host,
                capture_output=True
            )
            password = result.stdout.strip()
            if password:
                info['dashboard_password'] = password
            else:
                info['dashboard_password'] = "See bootstrap output above"
        except Exception:
            info['dashboard_password'] = "See bootstrap output above"
    
    # OSD count
    try:
        result = run_command(
            "cephadm shell -- ceph osd stat",
            host=bootstrap_host,
            capture_output=True
        )
        info['osd_stat'] = result.stdout.strip()
    except Exception:
        info['osd_stat'] = "Unable to retrieve"
    
    # Host list
    try:
        result = run_command(
            "cephadm shell -- ceph orch host ls",
            host=bootstrap_host,
            capture_output=True
        )
        info['hosts'] = result.stdout
    except Exception:
        info['hosts'] = "Unable to retrieve"
    
    return info


def print_summary(cluster_info: dict, ceph_version: str, container_image: str):
    """Print deployment summary."""
    summary = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                    DEPLOYMENT COMPLETE                           ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}

{Colors.CYAN}IBM Storage Ceph Version:{Colors.RESET} {ceph_version}
{Colors.CYAN}Container Image:{Colors.RESET} {container_image}

{Colors.CYAN}━━━ Cluster Status ━━━{Colors.RESET}
{cluster_info.get('status', 'N/A')}

{Colors.CYAN}━━━ OSD Status ━━━{Colors.RESET}
{cluster_info.get('osd_stat', 'N/A')}

{Colors.CYAN}━━━ Cluster Hosts ━━━{Colors.RESET}
{cluster_info.get('hosts', 'N/A')}

{Colors.CYAN}━━━ Dashboard & Monitoring ━━━{Colors.RESET}
  Dashboard URL:    {Colors.GREEN}{cluster_info.get('dashboard_url', 'N/A')}{Colors.RESET}
  Dashboard User:   {Colors.GREEN}admin{Colors.RESET}
  Dashboard Pass:   {Colors.GREEN}{cluster_info.get('dashboard_password', 'N/A')}{Colors.RESET}
  Prometheus URL:   {cluster_info.get('prometheus_url', 'N/A')}

{Colors.YELLOW}Note: Change the dashboard password after first login!{Colors.RESET}

{Colors.CYAN}━━━ Useful Commands ━━━{Colors.RESET}
  Cluster status:   cephadm shell -- ceph -s
  OSD tree:         cephadm shell -- ceph osd tree
  Service status:   cephadm shell -- ceph orch ls
  Host status:      cephadm shell -- ceph orch host ls
"""
    print(summary)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="IBM Storage Ceph Automated Deployment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic deployment with inventory file (latest Ceph 7.x)
  %(prog)s --inventory hosts.txt --ceph-version 7 --entitlement-key <KEY>

  # With SSH setup and custom cluster network (latest Ceph 8.x)
  %(prog)s --inventory hosts.txt --ceph-version 8 --entitlement-key <KEY> \\
           --setup-ssh --ssh-password <PASS> --cluster-network 10.10.0.0/24

  # Skip OSD deployment (configure manually later)
  %(prog)s --inventory hosts.txt --ceph-version 7 --entitlement-key <KEY> --skip-osd

Inventory file format (one per line):
  hostname1
  hostname2,192.168.1.102
  hostname3,192.168.1.103
        """
    )
    
    parser.add_argument(
        '--inventory', '-i',
        required=True,
        help='Path to hosts inventory file'
    )
    
    parser.add_argument(
        '--ceph-version', '-v',
        required=True,
        choices=list(VERSION_COMPATIBILITY.keys()),
        help='IBM Storage Ceph major version to deploy (latest release in that stream)'
    )
    
    parser.add_argument(
        '--entitlement-key', '-k',
        required=True,
        help='IBM entitlement key for container registry'
    )
    
    parser.add_argument(
        '--setup-ssh',
        action='store_true',
        help='Configure SSH passwordless authentication'
    )
    
    parser.add_argument(
        '--ssh-password',
        help='Current root password for SSH setup (required if --setup-ssh)'
    )
    
    parser.add_argument(
        '--cluster-network',
        help='Cluster network CIDR for internal traffic (e.g., 10.10.0.0/24)'
    )
    
    parser.add_argument(
        '--skip-osd',
        action='store_true',
        help='Skip automatic OSD deployment (deploy manually later)'
    )
    
    parser.add_argument(
        '--skip-firewall',
        action='store_true',
        help='Skip firewall configuration'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Continue deployment even with unsupported OS version (not recommended)'
    )
    
    parser.add_argument(
        '--skip-client-setup',
        action='store_true',
        help='Skip client node setup (ceph-common installation and config distribution)'
    )
    
    args = parser.parse_args()
    
    # Validate SSH arguments
    if args.setup_ssh and not args.ssh_password:
        parser.error("--ssh-password is required when --setup-ssh is specified")
    
    print_banner()
    
    # Total steps calculation
    total_steps = 8
    if args.setup_ssh:
        total_steps += 1
    if not args.skip_osd:
        total_steps += 1
    
    current_step = 0
    client_hosts = []  # Will be populated after parsing inventory
    
    try:
        # Step: Parse inventory
        current_step += 1
        log_step(current_step, total_steps, "Parsing inventory file")
        cluster_hosts, client_hosts = parse_inventory(args.inventory)
        
        if len(cluster_hosts) < 1:
            log_error("At least one cluster host is required in the inventory")
            sys.exit(1)
        
        log_info(f"Found {len(cluster_hosts)} cluster hosts in inventory:")
        for h in cluster_hosts:
            role = "(bootstrap)" if h.is_bootstrap else ""
            log_info(f"  • {h.hostname} {role}")
        
        if client_hosts:
            log_info(f"Found {len(client_hosts)} client hosts in inventory:")
            for h in client_hosts:
                log_info(f"  • {h.hostname} (client)")
            if not args.skip_client_setup:
                total_steps += 1  # Add step for client setup
        
        bootstrap_host = cluster_hosts[0]
        
        # Combine all hosts for SSH setup
        all_hosts = cluster_hosts + client_hosts
        
        # Step: SSH setup (optional)
        if args.setup_ssh:
            current_step += 1
            log_step(current_step, total_steps, "Setting up SSH passwordless authentication")
            setup_ssh_passwordless(all_hosts, args.ssh_password)
        
        # Step: Validate OS compatibility (cluster hosts only)
        current_step += 1
        log_step(current_step, total_steps, "Validating OS compatibility")
        
        has_warnings = False
        for host in cluster_hosts:
            log_info(f"Checking {host.hostname}...")
            host.os_version = get_os_version(host.hostname)
            log_info(f"  Detected: RHEL {host.os_version}")
            
            is_compatible, is_warning = validate_os_compatibility(
                args.ceph_version, host.os_version, host.is_bootstrap, args.force
            )
            
            if not is_compatible:
                log_error(f"OS compatibility check failed for {host.hostname}")
                sys.exit(1)
            
            if is_warning:
                has_warnings = True
            else:
                log_info(f"  ✓ Compatible with IBM Storage Ceph {args.ceph_version}")
        
        # Also get OS version for client hosts (for repo configuration)
        for host in client_hosts:
            host.os_version = get_os_version(host.hostname)
            log_info(f"  Client {host.hostname}: RHEL {host.os_version}")
        
        if has_warnings:
            log_warn("Proceeding with unsupported OS configuration due to --force flag")
        
        # Get bootstrap node IP
        bootstrap_ip = bootstrap_host.ip_address or get_host_ip(bootstrap_host.hostname)
        log_info(f"Bootstrap node IP: {bootstrap_ip}")
        
        # Determine container image based on Ceph version and bootstrap node OS
        bootstrap_rhel_major = bootstrap_host.os_version.split('.')[0]
        container_image = get_container_image(args.ceph_version, bootstrap_rhel_major)
        log_info(f"Container image: {container_image}")
        
        # Step: Configure repositories (parallel) - cluster hosts only
        current_step += 1
        log_step(current_step, total_steps, "Configuring IBM Storage Ceph repositories")
        configure_repositories_parallel(cluster_hosts, args.ceph_version)
        
        # Also configure repos on client hosts if not skipping client setup
        if client_hosts and not args.skip_client_setup:
            log_info("Configuring repositories on client hosts...")
            configure_repositories_parallel(client_hosts, args.ceph_version)
        
        # Step: Install packages (parallel) - cluster hosts only
        current_step += 1
        log_step(current_step, total_steps, "Installing required packages")
        install_packages_parallel(cluster_hosts, bootstrap_host.hostname)
        
        # Step: Configure firewall (parallel) - cluster hosts only
        if not args.skip_firewall:
            current_step += 1
            log_step(current_step, total_steps, "Configuring firewall rules")
            configure_firewall_parallel(cluster_hosts)
        
        # Step: Registry login (parallel) - cluster hosts only
        current_step += 1
        log_step(current_step, total_steps, "Authenticating to IBM Entitled Registry")
        registry_login_parallel(cluster_hosts, args.entitlement_key)
        
        # Step: Bootstrap cluster
        current_step += 1
        log_step(current_step, total_steps, "Bootstrapping Ceph cluster")
        
        bootstrap_info = bootstrap_cluster(
            bootstrap_host,
            bootstrap_ip,
            args.entitlement_key,
            container_image,
            args.cluster_network
        )
        
        # Step: Add additional hosts and configure HA
        current_step += 1
        log_step(current_step, total_steps, "Expanding cluster and configuring HA")
        
        if len(cluster_hosts) > 1:
            distribute_ssh_keys(bootstrap_host.hostname, cluster_hosts)
            add_hosts_to_cluster(bootstrap_host.hostname, cluster_hosts)
        
        # Configure 3 MONs and MGRs for HA
        configure_mon_mgr_placement(bootstrap_host.hostname, len(cluster_hosts))
        
        # Step: Deploy OSDs (optional)
        if not args.skip_osd:
            current_step += 1
            log_step(current_step, total_steps, "Deploying OSDs on all available devices")
            deploy_osds(bootstrap_host.hostname)
            
            # Give OSDs time to start deploying
            log_info("Waiting for OSD deployment to progress...")
            time.sleep(30)
        
        # Step: Setup client nodes (optional)
        if client_hosts and not args.skip_client_setup:
            current_step += 1
            log_step(current_step, total_steps, "Setting up client nodes")
            setup_client_nodes(bootstrap_host.hostname, client_hosts)
        
        # Final step: Gather info and print summary
        current_step += 1
        log_step(current_step, total_steps, "Gathering cluster information")
        
        wait_for_cluster_health(bootstrap_host.hostname)
        cluster_info = get_cluster_info(bootstrap_host.hostname, bootstrap_info)
        print_summary(cluster_info, args.ceph_version, container_image)
        
        log_info("Deployment completed successfully!")
        
    except FileNotFoundError as e:
        log_error(str(e))
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        log_error(f"Command execution failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        log_warn("\nDeployment interrupted by user")
        sys.exit(130)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()