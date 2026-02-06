#!/usr/bin/env python3
"""
IBM Storage Ceph Deployment Tool
=================================
Single-script deployment tool for IBM Storage Ceph clusters using cephadm.

Usage:
    ./deploy_ceph.py list-versions
    ./deploy_ceph.py deploy --hosts hosts.yml --version 8.0
    ./deploy_ceph.py setup-ssh --hosts hosts.yml
"""

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)


# =============================================================================
# Version and OS Compatibility Matrix (from IBM Documentation)
# =============================================================================

# IBM Ceph version -> supported OS versions and container image info
# Source: https://www.ibm.com/docs/en/storage-ceph
VERSION_MATRIX = {
    "8.0": {
        "upstream": "squid",
        "ceph_version": "19.2",
        "supported_os": {
            "rhel": ["9.4", "9.5", "9.6"],
            "rocky": ["9.4", "9.5"],
            "almalinux": ["9.4", "9.5"],
        },
        "repo_urls": {
            "9": "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-8-rhel-9.repo",
        },
        "image_tag": "8-latest",
        "release_date": "2024-11",
        "notes": "NVMe-oF gateway, SMB support (Tech Preview)",
    },
    "7.1": {
        "upstream": "reef",
        "ceph_version": "18.2",
        "supported_os": {
            "rhel": ["8.8", "8.9", "8.10", "9.2", "9.4"],
            "rocky": ["8.8", "8.9", "9.2", "9.4"],
            "almalinux": ["8.8", "8.9", "9.2", "9.4"],
        },
        "repo_urls": {
            "8": "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-7-rhel-8.repo",
            "9": "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-7-rhel-9.repo",
        },
        "image_tag": "7-latest",
        "release_date": "2024-06",
        "notes": "Latest Reef-based release",
    },
    "7.0": {
        "upstream": "reef",
        "ceph_version": "18.2",
        "supported_os": {
            "rhel": ["8.6", "8.7", "8.8", "9.0", "9.2"],
            "rocky": ["8.6", "8.7", "8.8", "9.0", "9.2"],
            "almalinux": ["8.6", "8.7", "8.8", "9.0", "9.2"],
        },
        "repo_urls": {
            "8": "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-7-rhel-8.repo",
            "9": "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-7-rhel-9.repo",
        },
        "image_tag": "7.0",
        "release_date": "2023-12",
        "notes": "Initial Reef release",
    },
    "6.1": {
        "upstream": "quincy",
        "ceph_version": "17.2",
        "supported_os": {
            "rhel": ["8.4", "8.5", "8.6", "8.7", "8.8", "9.0", "9.2"],
            "rocky": ["8.4", "8.5", "8.6", "8.7", "8.8"],
            "almalinux": ["8.4", "8.5", "8.6", "8.7", "8.8"],
        },
        "repo_urls": {
            "8": "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-6-rhel-8.repo",
            "9": "https://public.dhe.ibm.com/ibmdl/export/pub/storage/ceph/ibm-storage-ceph-6-rhel-9.repo",
        },
        "image_tag": "6-latest",
        "release_date": "2023-05",
        "notes": "Quincy-based (maintenance)",
    },
}

IBM_REGISTRY = "cp.icr.io/cp"
IBM_CEPH_IMAGE = "cp.icr.io/cp/ibm-ceph/ceph"

# Required firewall ports
CEPH_PORTS = {
    "mon": ["3300/tcp", "6789/tcp"],
    "osd": ["6800-7300/tcp"],
    "mgr": ["6800-7300/tcp"],
    "dashboard": ["8443/tcp"],
    "prometheus": ["9283/tcp"],
    "rgw": ["8080/tcp"],
    "mds": ["6800-7300/tcp"],
}


# =============================================================================
# Utility Functions
# =============================================================================

def run_cmd(cmd: list[str], capture: bool = True, check: bool = True,
            timeout: int = 300, stdin_data: str = None) -> subprocess.CompletedProcess:
    """Run a command and return result."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check,
            timeout=timeout,
            input=stdin_data
        )
        return result
    except subprocess.CalledProcessError as e:
        if capture:
            print(f"Command failed: {' '.join(cmd)}", file=sys.stderr)
            if e.stderr:
                print(f"stderr: {e.stderr}", file=sys.stderr)
        raise
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd)}", file=sys.stderr)
        raise


def run_remote(host: str, cmd: str, user: str = "root", 
               check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run command on remote host via SSH."""
    ssh_cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={min(timeout, 10)}",
        f"{user}@{host}", cmd
    ]
    return run_cmd(ssh_cmd, check=check, timeout=timeout)


def copy_to_remote(host: str, local_path: str, remote_path: str, 
                   user: str = "root") -> bool:
    """Copy file to remote host via SCP."""
    scp_cmd = [
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        local_path, f"{user}@{host}:{remote_path}"
    ]
    try:
        run_cmd(scp_cmd, timeout=60)
        return True
    except Exception:
        return False


def print_section(title: str):
    """Print section header."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def print_status(msg: str, status: str = "INFO"):
    """Print status message."""
    symbols = {"OK": "✓", "FAIL": "✗", "WARN": "!", "INFO": "→", "SKIP": "-"}
    symbol = symbols.get(status, "→")
    print(f"  [{symbol}] {msg}")


# =============================================================================
# OS Detection and Version Compatibility
# =============================================================================

@dataclass
class OSInfo:
    """Operating system information."""
    distro: str  # rhel, rocky, almalinux
    version: str  # e.g., "9.4"
    major: str   # e.g., "9"
    name: str = ""  # Pretty name
    
    @classmethod
    def detect(cls) -> "OSInfo":
        """Detect current OS from /etc/os-release."""
        os_release = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        os_release[key] = value.strip('"')
        except FileNotFoundError:
            return cls("unknown", "0.0", "0", "Unknown")
        
        distro_id = os_release.get("ID", "").lower()
        version = os_release.get("VERSION_ID", "0.0")
        name = os_release.get("PRETTY_NAME", distro_id)
        
        # Normalize distro names
        if distro_id in ["rhel", "redhat"]:
            distro = "rhel"
        elif distro_id == "rocky":
            distro = "rocky"
        elif distro_id == "almalinux":
            distro = "almalinux"
        elif distro_id == "centos":
            distro = "rhel"  # Treat CentOS as RHEL-compatible
        else:
            distro = distro_id
        
        major = version.split(".")[0]
        return cls(distro, version, major, name)
    
    @classmethod
    def detect_remote(cls, host: str, user: str = "root") -> "OSInfo":
        """Detect OS on remote host."""
        try:
            result = run_remote(host, "cat /etc/os-release", user=user, check=True)
            os_release = {}
            for line in result.stdout.splitlines():
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    os_release[key] = value.strip('"')
            
            distro_id = os_release.get("ID", "").lower()
            version = os_release.get("VERSION_ID", "0.0")
            name = os_release.get("PRETTY_NAME", distro_id)
            
            if distro_id in ["rhel", "redhat"]:
                distro = "rhel"
            elif distro_id == "rocky":
                distro = "rocky"
            elif distro_id == "almalinux":
                distro = "almalinux"
            else:
                distro = distro_id
            
            major = version.split(".")[0]
            return cls(distro, version, major, name)
        except Exception:
            return cls("unknown", "0.0", "0", "Unknown")


def get_compatible_versions(os_info: OSInfo) -> dict:
    """
    Get IBM Ceph versions compatible with the given OS.
    Returns dict with compatibility level: 'full', 'partial', or not included.
    """
    compatible = {}
    
    for version, info in VERSION_MATRIX.items():
        supported = info["supported_os"].get(os_info.distro, [])
        
        # Exact version match
        if os_info.version in supported:
            compatible[version] = {**info, "compatibility": "full"}
        # Check if any version with same major is supported (partial match)
        elif any(s.startswith(os_info.major + ".") for s in supported):
            compatible[version] = {**info, "compatibility": "partial"}
    
    return compatible


def get_recommended_version(os_info: OSInfo) -> Optional[str]:
    """Get the recommended version for the OS."""
    compatible = get_compatible_versions(os_info)
    
    # Prefer fully compatible, then partial, sorted by version descending
    full = [v for v, info in compatible.items() if info["compatibility"] == "full"]
    partial = [v for v, info in compatible.items() if info["compatibility"] == "partial"]
    
    if full:
        return sorted(full, reverse=True)[0]
    if partial:
        return sorted(partial, reverse=True)[0]
    return None


def get_repo_url(version: str, os_major: str) -> str:
    """Get repository URL for version and OS."""
    if version not in VERSION_MATRIX:
        return ""
    return VERSION_MATRIX[version]["repo_urls"].get(os_major, "")


def get_container_image(version: str) -> str:
    """Get container image for version."""
    if version not in VERSION_MATRIX:
        return ""
    tag = VERSION_MATRIX[version]["image_tag"]
    return f"{IBM_CEPH_IMAGE}:{tag}"


# =============================================================================
# SSH Setup and Distribution
# =============================================================================

class SSHManager:
    """Manage SSH keys with support for multiple key types."""
    
    def __init__(self, key_path: str = None, user: str = "root"):
        self.user = user
        # Try to find an existing key if none provided
        if key_path:
            self.key_path = Path(key_path).expanduser()
        else:
            self.key_path = self._detect_existing_key()
            
        self.pub_key_path = Path(f"{self.key_path}.pub")
    
    def _detect_existing_key(self) -> Path:
        """Detect the first available standard SSH key."""
        ssh_dir = Path.home() / ".ssh"
        # Priorities: Ed25519 is modern/preferred, then RSA
        for key_name in ["id_ed25519", "id_ecdsa", "id_rsa"]:
            path = ssh_dir / key_name
            if path.exists():
                return path
        # Fallback to default if nothing found
        return ssh_dir / "id_rsa"

    def key_exists(self) -> bool:
        """Check if both private and public key parts exist."""
        return self.key_path.exists() and self.pub_key_path.exists()

    def generate_key(self, comment: str = "ceph-deploy") -> bool:
        """Generate a modern Ed25519 key pair if none exists."""
        if self.key_exists():
            print_status(f"Using existing key: {self.key_path}", "SKIP")
            return True
        
        # Guard: If private exists but pub is missing, don't overwrite
        if self.key_path.exists():
            print_status(f"Private key {self.key_path} exists but .pub is missing. Script will not overwrite.", "FAIL")
            return False

        print_status(f"Generating new Ed25519 key: {self.key_path}")
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        
        try:
            # We use ed25519 now as it is the modern standard seen in your logs
            run_cmd([
                "ssh-keygen", "-t", "ed25519",
                "-f", str(self.key_path),
                "-N", "", 
                "-C", comment
            ])
            print_status("Key generated", "OK")
            return True
        except Exception as e:
            print_status(f"Failed to generate key: {e}", "FAIL")
            return False
    
    def get_public_key(self) -> str:
        """Read public key content."""
        if not self.pub_key_path.exists():
            return ""
        return self.pub_key_path.read_text().strip()
    
    def test_connection(self, host: str) -> tuple[bool, str]:
        """
        Test SSH connection to host.
        Returns (success, error_message).
        """
        try:
            result = run_cmd([
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                f"{self.user}@{host}",
                "echo 'SSH_OK'"
            ], check=False, timeout=10)
            
            if result.returncode == 0 and "SSH_OK" in result.stdout:
                return True, ""
            else:
                return False, result.stderr.strip() or "Connection failed"
        except subprocess.TimeoutExpired:
            return False, "Connection timeout"
        except Exception as e:
            return False, str(e)
    
    def distribute_key(self, host: str, password: str = None) -> tuple[bool, str]:
        """
        Distribute SSH key to remote host.
        Returns (success, error_message).
        """
        # First test if key-based auth already works
        success, _ = self.test_connection(host)
        if success:
            return True, "Key already authorized"
        
        if not self.key_exists():
            return False, "No SSH key exists. Run generate_key() first."
        
        pub_key = self.get_public_key()
        if not pub_key:
            return False, "Could not read public key"
        
        # Try ssh-copy-id if password provided
        if password:
            try:
                # Use sshpass for password-based ssh-copy-id
                if shutil.which("sshpass"):
                    result = run_cmd([
                        "sshpass", "-p", password,
                        "ssh-copy-id", "-o", "StrictHostKeyChecking=no",
                        "-i", str(self.pub_key_path),
                        f"{self.user}@{host}"
                    ], check=False, timeout=30)
                    
                    if result.returncode == 0:
                        return True, "Key distributed via ssh-copy-id"
                    return False, result.stderr.strip() or "ssh-copy-id failed"
                else:
                    return False, "sshpass not installed - required for automated key distribution"
            except Exception as e:
                return False, str(e)
        
        return False, "Password required for key distribution"
    
    def setup_hosts(self, hosts: list[dict], password: str = None) -> dict:
        """
        Setup SSH for multiple hosts.
        Returns dict of {host: (success, message)}.
        """
        results = {}
        
        # Generate key if needed
        if not self.key_exists():
            if not self.generate_key():
                return {h.get("addr", h.get("hostname")): (False, "Key generation failed") for h in hosts}
        
        for host_info in hosts:
            addr = host_info.get("addr", host_info.get("hostname"))
            success, msg = self.test_connection(addr)
            
            if success:
                results[addr] = (True, "SSH already working")
            elif password:
                success, msg = self.distribute_key(addr, password)
                results[addr] = (success, msg)
            else:
                results[addr] = (False, "SSH failed and no password provided")
        
        return results
    
    def print_manual_instructions(self, failed_hosts: list):
        """Print manual SSH setup instructions."""
        print("\n" + "="*60)
        print(" MANUAL SSH SETUP REQUIRED")
        print("="*60)
        print(f"\nFailed hosts: {', '.join(failed_hosts)}")
        print("\nOption 1: Use ssh-copy-id (requires password)")
        print("-" * 40)
        for host in failed_hosts:
            print(f"  ssh-copy-id -i {self.pub_key_path} {self.user}@{host}")
        
        print("\nOption 2: Manual key copy")
        print("-" * 40)
        print(f"Copy this public key to ~/.ssh/authorized_keys on each host:\n")
        print(f"  {self.get_public_key()}")
        
        print("\nOption 3: Install sshpass and re-run with --prompt-password")
        print("-" * 40)
        print("  dnf install sshpass")
        print(f"  {sys.argv[0]} setup-ssh --hosts <file> --prompt-password")
        print()


# =============================================================================
# Hosts Configuration
# =============================================================================

@dataclass
class HostConfig:
    """Configuration for a cluster host."""
    hostname: str
    addr: str
    labels: list[str] = field(default_factory=list)
    osd_devices: list[str] = field(default_factory=list)


def load_hosts_file(path: Path) -> list[HostConfig]:
    """
    Load hosts from YAML file.
    
    Supports formats:
    1. Simple list: [{hostname: x, addr: y, labels: [...]}]
    2. Grouped: {mons: [{...}], osds: [{...}]}
    3. Dict style: {mons: {host1: {addr: x}}}
    """
    with open(path) as f:
        data = yaml.safe_load(f)
    
    hosts = []
    seen = set()
    
    def add_host(hostname: str, addr: str, labels: list, osd_devices: list):
        if hostname in seen:
            # Merge labels
            for h in hosts:
                if h.hostname == hostname:
                    h.labels = list(set(h.labels + labels))
                    if osd_devices:
                        h.osd_devices = osd_devices
                    break
        else:
            seen.add(hostname)
            hosts.append(HostConfig(
                hostname=hostname,
                addr=addr,
                labels=labels,
                osd_devices=osd_devices
            ))
    
    # Simple list format
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                add_host(item, item, [], [])
            elif isinstance(item, dict):
                hostname = item.get("hostname", item.get("addr", ""))
                addr = item.get("addr", item.get("hostname", ""))
                labels = item.get("labels", [])
                osd_devices = item.get("osd_devices", [])
                add_host(hostname, addr, labels, osd_devices)
    
    # Grouped format
    elif isinstance(data, dict):
        for group, group_hosts in data.items():
            if group in ["all", "vars", "_meta"]:
                continue
            if not isinstance(group_hosts, (list, dict)):
                continue
            
            # List of hosts in group
            if isinstance(group_hosts, list):
                for item in group_hosts:
                    if isinstance(item, str):
                        add_host(item, item, [group], [])
                    elif isinstance(item, dict):
                        hostname = item.get("hostname", item.get("addr", ""))
                        addr = item.get("addr", item.get("hostname", item.get("ansible_host", "")))
                        labels = [group] + item.get("labels", [])
                        osd_devices = item.get("osd_devices", [])
                        add_host(hostname, addr, labels, osd_devices)
            
            # Dict format: {host1: {addr: x}}
            elif isinstance(group_hosts, dict):
                for hostname, props in group_hosts.items():
                    props = props or {}
                    addr = props.get("addr", props.get("ansible_host", hostname))
                    labels = [group] + props.get("labels", [])
                    osd_devices = props.get("osd_devices", [])
                    add_host(hostname, addr, labels, osd_devices)
    
    return hosts


def generate_sample_hosts_file(num_nodes: int = 3) -> str:
    """Generate sample hosts YAML."""
    hosts = []
    for i in range(num_nodes):
        # First 3 nodes get all roles, rest are OSD only
        if i < 3:
            labels = ["mon", "mgr", "osd"]
        else:
            labels = ["osd"]
        
        hosts.append({
            "hostname": f"ceph-node{i+1}",
            "addr": f"192.168.1.{10+i+1}",
            "labels": labels,
        })
    
    output = "# IBM Storage Ceph - Hosts Configuration\n"
    output += "# ======================================\n"
    output += "# Edit hostnames and IPs for your environment\n"
    output += "#\n"
    output += "# Labels determine service placement:\n"
    output += "#   mon - Monitor (3 or 5 recommended)\n"
    output += "#   mgr - Manager (2-3 for HA)\n"
    output += "#   osd - Storage (all storage nodes)\n"
    output += "#\n"
    output += "# Optional per-host OSD devices:\n"
    output += "#   osd_devices: [/dev/sdb, /dev/sdc]\n"
    output += "\n"
    output += yaml.dump(hosts, default_flow_style=False)
    
    return output


# =============================================================================
# Preflight Checks and Setup
# =============================================================================

class PreflightManager:
    """Handle preflight checks and node preparation."""
    
    def __init__(self, version: str, os_info: OSInfo):
        self.version = version
        self.os_info = os_info
        self.repo_url = get_repo_url(version, os_info.major)
    
    def check_local(self) -> dict:
        """Run preflight checks on local node."""
        results = {}
        
        # Check OS compatibility
        compatible = get_compatible_versions(self.os_info)
        if self.version in compatible:
            compat_level = compatible[self.version]["compatibility"]
            results["os_compatible"] = (
                compat_level == "full",
                f"{self.os_info.distro} {self.os_info.version} ({compat_level} support)"
            )
        else:
            results["os_compatible"] = (
                False,
                f"{self.os_info.distro} {self.os_info.version} not supported"
            )
        
        # Check required commands
        for cmd in ["podman", "python3", "chronyc"]:
            if shutil.which(cmd):
                results[f"cmd_{cmd}"] = (True, "installed")
            else:
                results[f"cmd_{cmd}"] = (False, "not found")
        
        # Check cephadm
        if shutil.which("cephadm"):
            results["cephadm"] = (True, "installed")
        else:
            results["cephadm"] = (False, "not installed (will install)")
        
        # Check time sync
        try:
            result = run_cmd(["chronyc", "tracking"], check=False)
            if "Leap status" in result.stdout and "Normal" in result.stdout:
                results["time_sync"] = (True, "synchronized")
            else:
                results["time_sync"] = (False, "not synchronized")
        except Exception:
            results["time_sync"] = (False, "chrony not running")
        
        return results
    
    def install_packages(self, remote_host: str = None) -> bool:
        """Install required packages."""
        packages = ["chrony", "podman", "python3", "lvm2"]
        
        if remote_host:
            cmd = f"dnf install -y {' '.join(packages)}"
            try:
                run_remote(remote_host, cmd, timeout=300)
                return True
            except Exception:
                return False
        else:
            try:
                run_cmd(["dnf", "install", "-y"] + packages, timeout=300)
                return True
            except Exception:
                return False
    
    def setup_repo(self, remote_host: str = None) -> bool:
        """Configure IBM Ceph repository."""
        if not self.repo_url:
            print_status(f"No repo URL for {self.version} on RHEL {self.os_info.major}", "FAIL")
            return False
        
        repo_file = "/etc/yum.repos.d/ibm-storage-ceph.repo"
        
        if remote_host:
            cmd = f"curl -s {self.repo_url} -o {repo_file}"
            try:
                run_remote(remote_host, cmd)
                return True
            except Exception:
                return False
        else:
            try:
                run_cmd(["curl", "-s", self.repo_url, "-o", repo_file])
                return True
            except Exception:
                return False
    
    def install_cephadm(self, remote_host: str = None) -> bool:
        """Install cephadm package."""
        if remote_host:
            try:
                run_remote(remote_host, "dnf install -y cephadm", timeout=120)
                return True
            except Exception:
                return False
        else:
            try:
                run_cmd(["dnf", "install", "-y", "cephadm"], timeout=120)
                return True
            except Exception:
                return False
    
    def configure_firewall(self, services: list[str] = None, 
                           remote_host: str = None) -> bool:
        """Configure firewall for Ceph services."""
        if services is None:
            services = ["mon", "osd", "mgr", "dashboard", "prometheus"]
        
        ports = []
        for svc in services:
            ports.extend(CEPH_PORTS.get(svc, []))
        
        if not ports:
            return True
        
        cmds = [f"firewall-cmd --permanent --add-port={p}" for p in ports]
        cmds.append("firewall-cmd --reload")
        
        if remote_host:
            try:
                for cmd in cmds:
                    run_remote(remote_host, cmd, check=False)
                return True
            except Exception:
                return False
        else:
            try:
                for cmd in cmds:
                    run_cmd(cmd.split(), check=False)
                return True
            except Exception:
                return False
    
    def enable_chronyd(self, remote_host: str = None) -> bool:
        """Enable and start chronyd."""
        if remote_host:
            try:
                run_remote(remote_host, "systemctl enable --now chronyd")
                return True
            except Exception:
                return False
        else:
            try:
                run_cmd(["systemctl", "enable", "--now", "chronyd"])
                return True
            except Exception:
                return False
    
    def prepare_node(self, remote_host: str = None, quiet: bool = False) -> dict:
        """Run full preparation on a node."""
        results = {}
        target = remote_host or "localhost"
        
        if not quiet:
            print_status(f"Preparing node: {target}")
        
        # Setup repo
        if self.setup_repo(remote_host):
            results["repo"] = (True, "configured")
        else:
            results["repo"] = (False, "failed")
        
        # Install packages
        if self.install_packages(remote_host):
            results["packages"] = (True, "installed")
        else:
            results["packages"] = (False, "failed")
        
        # Install cephadm
        if self.install_cephadm(remote_host):
            results["cephadm"] = (True, "installed")
        else:
            results["cephadm"] = (False, "failed")
        
        # Enable time sync
        if self.enable_chronyd(remote_host):
            results["chronyd"] = (True, "enabled")
        else:
            results["chronyd"] = (False, "failed")
        
        # Configure firewall
        if self.configure_firewall(remote_host=remote_host):
            results["firewall"] = (True, "configured")
        else:
            results["firewall"] = (False, "failed")
        
        return results


# =============================================================================
# Ceph Cluster Deployment
# =============================================================================

class CephDeployer:
    """Deploy and manage Ceph cluster using cephadm."""
    
    def __init__(self, version: str, registry_user: str = "cp", 
                 registry_password: str = ""):
        self.version = version
        self.registry_user = registry_user
        self.registry_password = registry_password
        self.image = get_container_image(version)
    
    def is_bootstrapped(self) -> bool:
        """Check if cluster is already bootstrapped."""
        return Path("/etc/ceph/ceph.conf").exists()
    
    def login_registry(self) -> bool:
        """Login to IBM container registry."""
        if not self.registry_password:
            print_status("No registry password provided", "WARN")
            return False
        
        try:
            run_cmd([
                "podman", "login", IBM_REGISTRY,
                "-u", self.registry_user,
                "-p", self.registry_password
            ])
            print_status("Registry login successful", "OK")
            return True
        except Exception as e:
            print_status(f"Registry login failed: {e}", "FAIL")
            return False
    
    def bootstrap(self, mon_ip: str, cluster_network: str = None,
                  dashboard_password: str = "admin") -> bool:
        """Bootstrap new Ceph cluster."""
        if self.is_bootstrapped():
            print_status("Cluster already bootstrapped", "SKIP")
            return True
        
        print_status(f"Bootstrapping cluster with MON IP: {mon_ip}")
        print_status(f"Using image: {self.image}")
        
        cmd = [
            "cephadm", "bootstrap",
            "--mon-ip", mon_ip,
            "--image", self.image,
            "--registry-url", IBM_REGISTRY,
            "--registry-username", self.registry_user,
            "--registry-password", self.registry_password,
            "--initial-dashboard-password", dashboard_password,
            "--dashboard-password-noupdate",
            "--yes-i-know"
        ]
        
        if cluster_network:
            cmd.extend(["--cluster-network", cluster_network])
        
        try:
            # Run without capturing to show progress
            result = subprocess.run(cmd, timeout=600)
            if result.returncode == 0:
                print_status("Bootstrap complete", "OK")
                return True
            else:
                print_status("Bootstrap failed", "FAIL")
                return False
        except Exception as e:
            print_status(f"Bootstrap failed: {e}", "FAIL")
            return False
    
    def distribute_cluster_key(self, host: str) -> bool:
        """Distribute cluster SSH key to host."""
        key_path = Path("/etc/ceph/ceph.pub")
        if not key_path.exists():
            return False
        
        try:
            pub_key = key_path.read_text().strip()
            cmd = f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{pub_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
            run_remote(host, cmd)
            return True
        except Exception:
            return False
    
    def add_host(self, hostname: str, addr: str, labels: list[str] = None) -> bool:
        """Add host to cluster."""
        print_status(f"Adding host: {hostname} ({addr})")
        
        # Distribute SSH key first
        if not self.distribute_cluster_key(addr):
            print_status(f"Failed to distribute cluster SSH key to {addr}", "WARN")
        
        # Add host via ceph orch
        cmd = ["ceph", "orch", "host", "add", hostname, addr]
        if labels:
            cmd.extend(["--labels", ",".join(labels)])
        
        try:
            run_cmd(cmd)
            print_status(f"Host {hostname} added", "OK")
            return True
        except Exception as e:
            print_status(f"Failed to add host: {e}", "FAIL")
            return False
    
    def apply_service_spec(self, spec: str) -> bool:
        """Apply service specification."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(spec)
            spec_file = f.name
        
        try:
            run_cmd(["ceph", "orch", "apply", "-i", spec_file])
            return True
        except Exception as e:
            print_status(f"Failed to apply spec: {e}", "FAIL")
            return False
        finally:
            os.unlink(spec_file)
    
    def deploy_mons(self, count: int = 3, label: str = "mon") -> bool:
        """Deploy monitor services."""
        print_status(f"Deploying {count} MON(s) on label '{label}'")
        
        spec = f"""service_type: mon
placement:
  label: {label}
  count: {count}
"""
        return self.apply_service_spec(spec)
    
    def deploy_mgrs(self, count: int = 2, label: str = "mgr") -> bool:
        """Deploy manager services."""
        print_status(f"Deploying {count} MGR(s) on label '{label}'")
        
        spec = f"""service_type: mgr
placement:
  label: {label}
  count: {count}
"""
        return self.apply_service_spec(spec)
    
    def deploy_osds_all_devices(self, label: str = "osd") -> bool:
        """Deploy OSDs on all available devices."""
        print_status(f"Deploying OSDs on all available devices (label: {label})")
        
        spec = f"""service_type: osd
service_id: default
placement:
  label: {label}
spec:
  data_devices:
    all: true
"""
        return self.apply_service_spec(spec)
    
    def deploy_osds_devices(self, hostname: str, devices: list[str]) -> bool:
        """Deploy OSDs on specific devices."""
        print_status(f"Deploying OSDs on {hostname}: {devices}")
        
        device_list = "\n".join(f"      - {d}" for d in devices)
        spec = f"""service_type: osd
service_id: {hostname.replace('-', '_')}_osds
placement:
  hosts:
    - {hostname}
spec:
  data_devices:
    paths:
{device_list}
"""
        return self.apply_service_spec(spec)
    
    def get_status(self) -> dict:
        """Get cluster status."""
        status = {}
        
        try:
            result = run_cmd(["ceph", "health", "--format", "json"], check=False)
            status["health"] = json.loads(result.stdout) if result.returncode == 0 else {"status": "ERROR"}
        except Exception:
            status["health"] = {"status": "UNKNOWN"}
        
        try:
            result = run_cmd(["ceph", "orch", "host", "ls", "--format", "json"], check=False)
            status["hosts"] = json.loads(result.stdout) if result.returncode == 0 else []
        except Exception:
            status["hosts"] = []
        
        try:
            result = run_cmd(["ceph", "osd", "stat", "--format", "json"], check=False)
            status["osds"] = json.loads(result.stdout) if result.returncode == 0 else {}
        except Exception:
            status["osds"] = {}
        
        return status
    
    def wait_for_health(self, timeout: int = 300) -> bool:
        """Wait for cluster to reach HEALTH_OK or HEALTH_WARN."""
        import time
        
        print_status("Waiting for cluster health...")
        start = time.time()
        
        while time.time() - start < timeout:
            try:
                result = run_cmd(["ceph", "health"], check=False)
                if "HEALTH_OK" in result.stdout or "HEALTH_WARN" in result.stdout:
                    print_status(f"Cluster health: {result.stdout.strip()}", "OK")
                    return True
            except Exception:
                pass
            time.sleep(10)
        
        print_status("Timeout waiting for cluster health", "WARN")
        return False


# =============================================================================
# CLI Commands
# =============================================================================

def cmd_list_versions(args):
    """List available versions with OS compatibility."""
    os_info = OSInfo.detect()
    
    print_section("IBM Storage Ceph - Available Versions")
    print(f"\nCurrent OS: {os_info.name}")
    print(f"Detected:   {os_info.distro.upper()} {os_info.version}")
    print(f"Registry:   {IBM_REGISTRY}")
    
    compatible = get_compatible_versions(os_info)
    recommended = get_recommended_version(os_info)
    
    print("\n" + "-"*70)
    print(f"{'Version':<10} {'Upstream':<12} {'Supported RHEL':<28} {'Status':<15}")
    print("-"*70)
    
    for version in sorted(VERSION_MATRIX.keys(), reverse=True):
        info = VERSION_MATRIX[version]
        rhel_versions = info["supported_os"].get("rhel", [])
        rhel_str = ", ".join(rhel_versions[:5])
        if len(rhel_versions) > 5:
            rhel_str += "..."
        
        # Determine status
        if version == recommended:
            status = "✓ RECOMMENDED"
        elif version in compatible:
            compat = compatible[version]["compatibility"]
            status = "✓ Compatible" if compat == "full" else "~ Partial"
        else:
            status = "✗ Not supported"
        
        print(f"{version:<10} {info['upstream'].title():<12} {rhel_str:<28} {status:<15}")
    
    print("-"*70)
    
    # Recommendations
    if recommended:
        print(f"\n→ Recommended for your OS: IBM Ceph {recommended}")
        info = VERSION_MATRIX[recommended]
        print(f"  Based on: Ceph {info['upstream'].title()} ({info['ceph_version']})")
        print(f"  Image:    {get_container_image(recommended)}")
    else:
        print("\n⚠ No compatible version found for your OS.")
        print("  Supported distributions: RHEL, Rocky Linux, AlmaLinux")
        print("  For IBM Ceph 8.0: RHEL 9.4+")
        print("  For IBM Ceph 7.x: RHEL 8.6+ or 9.0+")
    
    return 0


def cmd_setup_ssh(args):
    """Setup SSH keys for cluster hosts."""
    print_section("SSH Key Setup")
    
    # Load hosts
    hosts = load_hosts_file(Path(args.hosts))
    if not hosts:
        print("ERROR: No hosts found in configuration", file=sys.stderr)
        return 1
    
    print(f"Hosts file: {args.hosts}")
    print(f"Total hosts: {len(hosts)}")
    
    # Initialize SSH manager
    ssh = SSHManager(user=args.user)
    
    # Generate key if needed
    if not ssh.key_exists():
        print_status("Generating SSH key pair")
        if not ssh.generate_key():
            return 1
    
    print_status(f"Using key: {ssh.key_path}")
    
    # Test connections
    print("\nTesting SSH connectivity:")
    print("-" * 60)
    
    failed_hosts = []
    for host in hosts:
        success, msg = ssh.test_connection(host.addr)
        if success:
            print_status(f"{host.hostname:<20} ({host.addr:<15}): OK", "OK")
        else:
            error_short = msg[:40] + "..." if len(msg) > 40 else msg
            print_status(f"{host.hostname:<20} ({host.addr:<15}): {error_short}", "FAIL")
            failed_hosts.append(host)
    
    if not failed_hosts:
        print("\n✓ All hosts accessible via SSH.")
        return 0
    
    print(f"\n{len(failed_hosts)} host(s) not accessible via SSH.")
    
    # Offer to distribute keys
    if args.password:
        password = args.password
    elif args.prompt_password:
        password = getpass.getpass("\nEnter SSH password for key distribution: ")
    else:
        ssh.print_manual_instructions([h.addr for h in failed_hosts])
        return 1
    
    # Distribute keys
    print("\nDistributing SSH keys:")
    print("-" * 60)
    
    results = ssh.setup_hosts([{"addr": h.addr, "hostname": h.hostname} for h in failed_hosts], password)
    
    success_count = 0
    for addr, (success, msg) in results.items():
        if success:
            success_count += 1
            print_status(f"{addr}: {msg}", "OK")
        else:
            print_status(f"{addr}: {msg}", "FAIL")
    
    print(f"\nSuccessfully configured: {success_count}/{len(failed_hosts)}")
    
    if success_count < len(failed_hosts):
        still_failed = [addr for addr, (s, _) in results.items() if not s]
        ssh.print_manual_instructions(still_failed)
        return 1
    
    return 0


def cmd_preflight(args):
    """Run preflight checks and preparation."""
    print_section("Preflight Checks")
    
    os_info = OSInfo.detect()
    print(f"Detected OS: {os_info.name}")
    print(f"Target version: IBM Ceph {args.version}")
    
    # Check compatibility
    compatible = get_compatible_versions(os_info)
    if args.version not in compatible:
        print(f"\nERROR: IBM Ceph {args.version} is not compatible with {os_info.distro} {os_info.version}")
        recommended = get_recommended_version(os_info)
        if recommended:
            print(f"Suggested: Use --version {recommended}")
        print("\nRun 'list-versions' to see all compatible versions.")
        return 1
    
    preflight = PreflightManager(args.version, os_info)
    
    # Run checks
    print("\nSystem checks:")
    print("-" * 50)
    results = preflight.check_local()
    
    all_ok = True
    for check, (success, msg) in results.items():
        status = "OK" if success else "FAIL"
        if not success:
            all_ok = False
        print_status(f"{check:<20}: {msg}", status)
    
    # Prepare if requested
    if args.prepare:
        print("\nPreparing local node:")
        print("-" * 50)
        prep_results = preflight.prepare_node(quiet=True)
        
        for step, (success, msg) in prep_results.items():
            status = "OK" if success else "FAIL"
            print_status(f"{step:<20}: {msg}", status)
    elif not all_ok:
        print("\nRun with --prepare to install required packages.")
    
    return 0


def cmd_deploy(args):
    """Deploy Ceph cluster."""
    print_section("IBM Storage Ceph Deployment")
    
    # Validate inputs
    os_info = OSInfo.detect()
    compatible = get_compatible_versions(os_info)
    
    if args.version not in compatible:
        print(f"ERROR: IBM Ceph {args.version} not compatible with {os_info.distro} {os_info.version}")
        recommended = get_recommended_version(os_info)
        if recommended:
            print(f"Recommended version: {recommended}")
        return 1
    
    if not args.registry_password:
        print("ERROR: --registry-password required")
        print("       Get your key from: https://myibm.ibm.com/products-services/containerlibrary")
        print("       Or set: export IBM_ENTITLEMENT_KEY=<your-key>")
        return 1
    
    # Load hosts
    hosts = load_hosts_file(Path(args.hosts))
    if not hosts:
        print("ERROR: No hosts found in configuration")
        return 1
    
    print(f"Version:      IBM Ceph {args.version}")
    print(f"Image:        {get_container_image(args.version)}")
    print(f"Hosts:        {len(hosts)}")
    print(f"Skip OSD:     {args.skip_osd}")
    
    # Verify SSH connectivity first
    print("\nVerifying SSH connectivity...")
    ssh = SSHManager()
    failed_ssh = []
    for host in hosts:
        success, _ = ssh.test_connection(host.addr)
        if not success:
            failed_ssh.append(host.hostname)
    
    if failed_ssh:
        print(f"\nERROR: Cannot SSH to hosts: {', '.join(failed_ssh)}")
        print("Run 'setup-ssh' first to configure SSH access.")
        return 1
    
    print_status("All hosts accessible", "OK")
    
    # Determine bootstrap host and MON IP
    bootstrap_host = hosts[0]
    mon_ip = args.mon_ip or bootstrap_host.addr
    
    # Initialize deployer
    deployer = CephDeployer(
        version=args.version,
        registry_user=args.registry_user,
        registry_password=args.registry_password
    )
    
    # Preflight on all hosts
    if not args.skip_preflight:
        print_section("Preflight Preparation")
        preflight = PreflightManager(args.version, os_info)
        
        # Prepare local node first
        print_status("Preparing local node...")
        preflight.prepare_node(quiet=True)
        
        # Prepare remote hosts
        for host in hosts[1:]:
            print_status(f"Preparing {host.hostname}...")
            # Detect remote OS
            remote_os = OSInfo.detect_remote(host.addr)
            remote_preflight = PreflightManager(args.version, remote_os)
            remote_preflight.prepare_node(host.addr, quiet=True)
    
    # Registry login
    print_section("Registry Login")
    if not deployer.login_registry():
        print("ERROR: Registry login failed")
        return 1
    
    # Bootstrap
    print_section("Cluster Bootstrap")
    if not deployer.bootstrap(mon_ip, args.cluster_network, args.dashboard_password):
        print("Bootstrap failed!")
        return 1
    
    # Add hosts
    if len(hosts) > 1:
        print_section("Adding Hosts")
        for host in hosts[1:]:  # Skip bootstrap host
            deployer.add_host(host.hostname, host.addr, host.labels)
    
    # Get host counts by role
    mon_hosts = [h for h in hosts if "mon" in h.labels]
    mgr_hosts = [h for h in hosts if "mgr" in h.labels]
    osd_hosts = [h for h in hosts if "osd" in h.labels]
    
    # Deploy MONs
    print_section("Deploying Monitors")
    mon_count = min(len(mon_hosts), 5) if mon_hosts else 1
    # Ensure odd number
    if mon_count > 1 and mon_count % 2 == 0:
        mon_count -= 1
    deployer.deploy_mons(count=mon_count)
    
    # Deploy MGRs
    print_section("Deploying Managers")
    mgr_count = min(len(mgr_hosts), 3) if mgr_hosts else 1
    deployer.deploy_mgrs(count=mgr_count)
    
    # Deploy OSDs
    if not args.skip_osd:
        print_section("Deploying OSDs")
        
        # Check for custom device specs
        custom_devices = [h for h in osd_hosts if h.osd_devices]
        
        if custom_devices:
            for host in custom_devices:
                deployer.deploy_osds_devices(host.hostname, host.osd_devices)
            # Deploy all devices on hosts without custom specs
            remaining = [h for h in osd_hosts if not h.osd_devices]
            if remaining:
                deployer.deploy_osds_all_devices()
        else:
            deployer.deploy_osds_all_devices()
    else:
        print_section("Skipping OSD Deployment")
        print_status("To deploy OSDs later, run:", "INFO")
        print_status("  ceph orch apply osd --all-available-devices", "INFO")
    
    # Wait for health
    print_section("Waiting for Cluster")
    deployer.wait_for_health()
    
    # Final status
    print_section("Deployment Complete")
    status = deployer.get_status()
    
    health_status = status["health"].get("status", "UNKNOWN")
    print(f"\nHealth:  {health_status}")
    print(f"Hosts:   {len(status['hosts'])}")
    print(f"OSDs:    {status['osds'].get('num_osds', 0)} total, {status['osds'].get('num_up_osds', 0)} up")
    
    # Dashboard info
    try:
        result = run_cmd(["ceph", "mgr", "services", "--format", "json"], check=False)
        services = json.loads(result.stdout)
        if "dashboard" in services:
            print(f"\nDashboard: {services['dashboard']}")
            print(f"Login:     admin / {args.dashboard_password}")
    except Exception:
        pass
    
    return 0


def cmd_generate_hosts(args):
    """Generate sample hosts file."""
    content = generate_sample_hosts_file(args.nodes)
    
    if args.output:
        Path(args.output).write_text(content)
        print(f"Generated: {args.output}")
        print(f"Edit the file with your hostnames and IPs, then run:")
        print(f"  {sys.argv[0]} setup-ssh --hosts {args.output}")
    else:
        print(content)
    
    return 0


def cmd_status(args):
    """Show cluster status."""
    deployer = CephDeployer(version="")
    
    if not deployer.is_bootstrapped():
        print("No cluster found on this host.")
        return 1
    
    print_section("Cluster Status")
    status = deployer.get_status()
    
    health = status["health"].get("status", "UNKNOWN")
    print(f"\nHealth: {health}")
    
    print(f"\nHosts ({len(status['hosts'])}):")
    for host in status["hosts"]:
        labels = host.get("labels", [])
        label_str = f" [{', '.join(labels)}]" if labels else ""
        print(f"  {host.get('hostname', 'unknown'):<20} {host.get('addr', 'unknown'):<15}{label_str}")
    
    osds = status["osds"]
    print(f"\nOSDs: {osds.get('num_osds', 0)} total, "
          f"{osds.get('num_up_osds', 0)} up, "
          f"{osds.get('num_in_osds', 0)} in")
    
    # Get services
    try:
        result = run_cmd(["ceph", "orch", "ls", "--format", "json"], check=False)
        if result.returncode == 0:
            services = json.loads(result.stdout)
            print(f"\nServices:")
            for svc in services:
                name = svc.get("service_name", "unknown")
                running = svc.get("running", 0)
                size = svc.get("size", 0)
                print(f"  {name:<20} {running}/{size} running")
    except Exception:
        pass
    
    return 0


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="IBM Storage Ceph Deployment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List versions compatible with your OS
  %(prog)s list-versions

  # Setup SSH access to all hosts
  %(prog)s setup-ssh --hosts hosts.yml --prompt-password

  # Run preflight checks
  %(prog)s preflight --version 8.0

  # Deploy cluster
  %(prog)s deploy --hosts hosts.yml --version 8.0 --registry-password <KEY>

  # Deploy without OSDs (add later)
  %(prog)s deploy --hosts hosts.yml --version 7.1 --skip-osd --registry-password <KEY>

  # Generate sample hosts file
  %(prog)s generate-hosts --nodes 5 -o hosts.yml

  # Check cluster status
  %(prog)s status
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # list-versions
    subparsers.add_parser("list-versions", help="List available versions with OS compatibility")
    
    # setup-ssh
    sub = subparsers.add_parser("setup-ssh", help="Setup SSH keys for cluster hosts")
    sub.add_argument("--hosts", required=True, help="Path to hosts YAML file")
    sub.add_argument("--user", default="root", help="SSH user (default: root)")
    sub.add_argument("--prompt-password", action="store_true", 
                     help="Prompt for password to distribute keys")
    sub.add_argument("--password", help="Password for key distribution (prefer --prompt-password)")
    
    # preflight
    sub = subparsers.add_parser("preflight", help="Run preflight checks")
    sub.add_argument("--version", required=True, choices=list(VERSION_MATRIX.keys()), 
                     help="Target IBM Ceph version")
    sub.add_argument("--prepare", action="store_true", 
                     help="Install packages and configure node")
    
    # deploy
    sub = subparsers.add_parser("deploy", help="Deploy Ceph cluster")
    sub.add_argument("--hosts", required=True, help="Path to hosts YAML file")
    sub.add_argument("--version", required=True, choices=list(VERSION_MATRIX.keys()), 
                     help="IBM Ceph version")
    sub.add_argument("--registry-user", default="cp", help="Registry username (default: cp)")
    sub.add_argument("--registry-password", 
                     default=os.environ.get("IBM_ENTITLEMENT_KEY", ""), 
                     help="IBM entitlement key (or set IBM_ENTITLEMENT_KEY env var)")
    sub.add_argument("--mon-ip", help="IP for first monitor (auto-detected if not set)")
    sub.add_argument("--cluster-network", help="Cluster network CIDR (e.g., 10.0.0.0/24)")
    sub.add_argument("--dashboard-password", default="admin", help="Dashboard admin password")
    sub.add_argument("--skip-osd", action="store_true", help="Skip OSD deployment")
    sub.add_argument("--skip-preflight", action="store_true", help="Skip preflight preparation")
    
    # generate-hosts
    sub = subparsers.add_parser("generate-hosts", help="Generate sample hosts file")
    sub.add_argument("--nodes", type=int, default=3, help="Number of nodes (default: 3)")
    sub.add_argument("-o", "--output", help="Output file (default: stdout)")
    
    # status
    subparsers.add_parser("status", help="Show cluster status")
    
    args = parser.parse_args()
    
    commands = {
        "list-versions": cmd_list_versions,
        "setup-ssh": cmd_setup_ssh,
        "preflight": cmd_preflight,
        "deploy": cmd_deploy,
        "generate-hosts": cmd_generate_hosts,
        "status": cmd_status,
    }
    
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
