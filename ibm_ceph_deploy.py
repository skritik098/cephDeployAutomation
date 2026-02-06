#!/usr/bin/env python3
"""
IBM Storage Ceph Automated Deployment Script
=============================================
Automates the deployment of IBM Storage Ceph clusters on RHEL-based systems.

Features:
- OS version validation against IBM supported configurations
- Optional SSH passwordless setup for root user
- Repository configuration based on Ceph and OS versions
- IBM Entitled Registry authentication
- Cephadm bootstrap with 3 MONs and MGRs
- Optional OSD deployment using all available devices

Author: Automated deployment tool
"""

import argparse
import subprocess
import sys
import os
import json
import time
import re
from dataclasses import dataclass
from typing import Optional
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
        "9": "cp.icr.io/cp/ibm-ceph/ceph-5-rhel9",
        "8": "cp.icr.io/cp/ibm-ceph/ceph-5-rhel8",
    },
}


@dataclass
class HostInfo:
    """Represents a host in the cluster."""
    hostname: str
    ip_address: Optional[str] = None
    is_bootstrap: bool = False
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
        # Try to get the IP that would be used to reach external networks
        result = run_command(
            "hostname -I | awk '{print $1}'",
            host=host,
            capture_output=True
        )
        ip = result.stdout.strip()
        if ip:
            return ip
        
        # Fallback: resolve hostname
        result = run_command(
            f"getent hosts {host} | awk '{{print $1}}'",
            capture_output=True
        )
        return result.stdout.strip()
    except Exception:
        log_warn(f"Could not determine IP for {host}, using hostname")
        return host


def validate_os_compatibility(ceph_version: str, os_version: str, is_bootstrap: bool = False) -> bool:
    """
    Validate if the OS version is compatible with the Ceph version.
    
    Args:
        ceph_version: IBM Storage Ceph major version (e.g., "7")
        os_version: RHEL version (e.g., "9.4")
        is_bootstrap: Whether this is the bootstrap node
    
    Returns:
        True if compatible, False otherwise
    """
    if ceph_version not in VERSION_COMPATIBILITY:
        log_error(f"Unknown Ceph version: {ceph_version}")
        log_info(f"Supported versions: {', '.join(VERSION_COMPATIBILITY.keys())}")
        return False
    
    rhel_major = os_version.split('.')[0]
    compat = VERSION_COMPATIBILITY[ceph_version]
    
    # Check if RHEL major version is supported
    if rhel_major not in compat:
        log_error(f"RHEL {rhel_major} is not supported for IBM Storage Ceph {ceph_version}")
        supported = [f"RHEL {k}" for k in compat.keys()]
        log_info(f"Supported OS versions: {', '.join(supported)}")
        return False
    
    # Check specific minor version
    if os_version not in compat[rhel_major]:
        log_error(f"RHEL {os_version} is not supported for IBM Storage Ceph {ceph_version}")
        log_info(f"Supported RHEL {rhel_major} versions: {', '.join(compat[rhel_major])}")
        return False
    
    # Check bootstrap node requirement for RHEL 8 clusters
    if rhel_major == "8" and ceph_version in RHEL9_BOOTSTRAP_REQUIRED:
        if is_bootstrap:
            log_error(f"IBM Storage Ceph {ceph_version} requires RHEL 9 for the bootstrap node")
            log_info("RHEL 8 nodes can only be added after bootstrapping from a RHEL 9 node")
            return False
        else:
            log_warn(f"RHEL 8 node detected - ensure bootstrap node is RHEL 9")
    
    return True


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


def parse_inventory(inventory_path: str) -> list[HostInfo]:
    """
    Parse hosts inventory file.
    
    Supported formats:
    - Simple: one hostname per line
    - With IP: hostname,ip_address per line
    - JSON: [{"hostname": "...", "ip": "..."}, ...]
    
    First host is assumed to be the bootstrap node.
    """
    hosts = []
    path = Path(inventory_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {inventory_path}")
    
    content = path.read_text().strip()
    
    # Try JSON format first
    if content.startswith('['):
        try:
            data = json.loads(content)
            for i, item in enumerate(data):
                if isinstance(item, str):
                    hosts.append(HostInfo(hostname=item, is_bootstrap=(i == 0)))
                elif isinstance(item, dict):
                    hosts.append(HostInfo(
                        hostname=item.get('hostname', item.get('host')),
                        ip_address=item.get('ip', item.get('ip_address')),
                        is_bootstrap=(i == 0)
                    ))
            return hosts
        except json.JSONDecodeError:
            pass
    
    # Parse line-by-line format
    for i, line in enumerate(content.splitlines()):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        parts = line.split(',')
        hostname = parts[0].strip()
        ip_address = parts[1].strip() if len(parts) > 1 else None
        
        hosts.append(HostInfo(
            hostname=hostname,
            ip_address=ip_address,
            is_bootstrap=(i == 0)
        ))
    
    return hosts


def setup_ssh_passwordless(hosts: list[HostInfo], ssh_password: str):
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


def configure_repositories(host: str, ceph_version: str, rhel_major: str):
    """
    Configure IBM Storage Ceph repositories on a host.
    
    Args:
        host: Target hostname
        ceph_version: Ceph major version (e.g., "7")
        rhel_major: RHEL major version (e.g., "9")
    """
    log_info(f"Configuring repositories on {host}...")
    
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


def install_packages(host: str, is_bootstrap: bool = False):
    """
    Install required packages on a host.
    
    Args:
        host: Target hostname
        is_bootstrap: Whether this is the bootstrap node
    """
    log_info(f"Installing packages on {host}...")
    
    # Base packages for all nodes
    packages = [
        "podman",
        "lvm2",
        "chrony",
        "ibm-storage-ceph-license",
    ]
    
    # Bootstrap node gets cephadm
    if is_bootstrap:
        packages.append("cephadm")
    
    # Install packages
    pkg_list = " ".join(packages)
    run_command(f"dnf install -y {pkg_list}", host=host, timeout=600)
    
    # Accept IBM license
    run_command(
        "mkdir -p /usr/share/ibm-storage-ceph-license && "
        "touch /usr/share/ibm-storage-ceph-license/accept",
        host=host
    )
    
    # Enable and start chronyd for time sync
    run_command("systemctl enable --now chronyd", host=host)
    
    log_info(f"  ✓ Packages installed on {host}")


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


def bootstrap_cluster(bootstrap_host: HostInfo, mon_ip: str, entitlement_key: str,
                      container_image: str, cluster_network: Optional[str] = None):
    """
    Bootstrap the Ceph cluster using cephadm.
    
    Args:
        bootstrap_host: Bootstrap node info
        mon_ip: IP address for the first monitor
        entitlement_key: IBM entitlement key
        container_image: Full container image path (e.g., cp.icr.io/cp/ibm-ceph/ceph-7-rhel9:latest)
        cluster_network: Optional cluster network CIDR
    """
    log_info(f"Bootstrapping Ceph cluster on {bootstrap_host.hostname}...")
    log_info(f"  Using container image: {container_image}")
    
    # Build bootstrap command with simple/default options
    bootstrap_cmd = [
        "cephadm bootstrap",
        f"--image {container_image}",
        f"--mon-ip {mon_ip}",
        f"--registry-url {IBM_REGISTRY_URL}",
        f"--registry-username {IBM_REGISTRY_USERNAME}",
        f"--registry-password {entitlement_key}",
    ]
    
    # Add cluster network if specified
    if cluster_network:
        bootstrap_cmd.append(f"--cluster-network {cluster_network}")
    
    cmd = " ".join(bootstrap_cmd)
    
    # Run bootstrap (this takes several minutes)
    log_info("  This may take 5-10 minutes...")
    result = run_command(cmd, host=bootstrap_host.hostname, timeout=900, capture_output=True)
    
    # Print bootstrap output
    if result.stdout:
        print(result.stdout)
    
    log_info("  ✓ Cluster bootstrap completed")
    
    return result.stdout


def distribute_ssh_keys(bootstrap_host: str, target_hosts: list[HostInfo]):
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


def add_hosts_to_cluster(bootstrap_host: str, hosts: list[HostInfo]):
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
    
    # List available devices first
    log_info("  Discovering available devices...")
    result = run_command(
        "cephadm shell -- ceph orch device ls --wide --refresh",
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


def get_cluster_info(bootstrap_host: str) -> dict:
    """
    Gather cluster information for final summary.
    
    Args:
        bootstrap_host: Bootstrap node hostname
    
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
    
    # Dashboard URL and credentials
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
    
    # Dashboard password (from bootstrap output file)
    try:
        result = run_command(
            "cat /etc/ceph/ceph.dashboard.password 2>/dev/null || echo 'Check bootstrap output'",
            host=bootstrap_host,
            capture_output=True
        )
        info['dashboard_password'] = result.stdout.strip()
    except Exception:
        info['dashboard_password'] = "Check bootstrap output"
    
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
    
    try:
        # Step: Parse inventory
        current_step += 1
        log_step(current_step, total_steps, "Parsing inventory file")
        hosts = parse_inventory(args.inventory)
        
        if len(hosts) < 1:
            log_error("At least one host is required in the inventory")
            sys.exit(1)
        
        log_info(f"Found {len(hosts)} hosts in inventory:")
        for h in hosts:
            role = "(bootstrap)" if h.is_bootstrap else ""
            log_info(f"  • {h.hostname} {role}")
        
        bootstrap_host = hosts[0]
        
        # Step: SSH setup (optional)
        if args.setup_ssh:
            current_step += 1
            log_step(current_step, total_steps, "Setting up SSH passwordless authentication")
            setup_ssh_passwordless(hosts, args.ssh_password)
        
        # Step: Validate OS compatibility
        current_step += 1
        log_step(current_step, total_steps, "Validating OS compatibility")
        
        for host in hosts:
            log_info(f"Checking {host.hostname}...")
            host.os_version = get_os_version(host.hostname)
            log_info(f"  Detected: RHEL {host.os_version}")
            
            if not validate_os_compatibility(args.ceph_version, host.os_version, host.is_bootstrap):
                log_error(f"OS compatibility check failed for {host.hostname}")
                sys.exit(1)
            
            log_info(f"  ✓ Compatible with IBM Storage Ceph {args.ceph_version}")
        
        # Get bootstrap node IP
        bootstrap_ip = bootstrap_host.ip_address or get_host_ip(bootstrap_host.hostname)
        log_info(f"Bootstrap node IP: {bootstrap_ip}")
        
        # Determine container image based on Ceph version and bootstrap node OS
        bootstrap_rhel_major = bootstrap_host.os_version.split('.')[0]
        container_image = get_container_image(args.ceph_version, bootstrap_rhel_major)
        log_info(f"Container image: {container_image}")
        
        # Step: Configure repositories
        current_step += 1
        log_step(current_step, total_steps, "Configuring IBM Storage Ceph repositories")
        
        for host in hosts:
            rhel_major = host.os_version.split('.')[0]
            configure_repositories(host.hostname, args.ceph_version, rhel_major)
        
        # Step: Install packages
        current_step += 1
        log_step(current_step, total_steps, "Installing required packages")
        
        for host in hosts:
            install_packages(host.hostname, host.is_bootstrap)
        
        # Step: Configure firewall
        if not args.skip_firewall:
            current_step += 1
            log_step(current_step, total_steps, "Configuring firewall rules")
            
            for host in hosts:
                configure_firewall(host.hostname)
        
        # Step: Registry login
        current_step += 1
        log_step(current_step, total_steps, "Authenticating to IBM Entitled Registry")
        
        for host in hosts:
            registry_login(host.hostname, args.entitlement_key)
        
        # Step: Bootstrap cluster
        current_step += 1
        log_step(current_step, total_steps, "Bootstrapping Ceph cluster")
        
        bootstrap_output = bootstrap_cluster(
            bootstrap_host,
            bootstrap_ip,
            args.entitlement_key,
            container_image,
            args.cluster_network
        )
        
        # Step: Add additional hosts and configure HA
        current_step += 1
        log_step(current_step, total_steps, "Expanding cluster and configuring HA")
        
        if len(hosts) > 1:
            distribute_ssh_keys(bootstrap_host.hostname, hosts)
            add_hosts_to_cluster(bootstrap_host.hostname, hosts)
        
        # Configure 3 MONs and MGRs for HA
        configure_mon_mgr_placement(bootstrap_host.hostname, len(hosts))
        
        # Step: Deploy OSDs (optional)
        if not args.skip_osd:
            current_step += 1
            log_step(current_step, total_steps, "Deploying OSDs on all available devices")
            deploy_osds(bootstrap_host.hostname)
            
            # Give OSDs time to start deploying
            log_info("Waiting for OSD deployment to progress...")
            time.sleep(30)
        
        # Final step: Gather info and print summary
        current_step += 1
        log_step(current_step, total_steps, "Gathering cluster information")
        
        wait_for_cluster_health(bootstrap_host.hostname)
        cluster_info = get_cluster_info(bootstrap_host.hostname)
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
