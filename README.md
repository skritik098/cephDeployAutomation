# IBM Storage Ceph Automated Deployment Tool

Automates end-to-end deployment of IBM Storage Ceph clusters on RHEL-based systems.

## Features

- **OS Version Validation**: Ensures RHEL version matches IBM's supported configuration matrix
- **Automatic Container Image Selection**: Selects correct IBM Storage Ceph container image based on version and OS
- **SSH Passwordless Setup**: Optional automatic SSH key distribution for root user
- **Multi-Version Support**: Supports IBM Storage Ceph major versions 5, 6, 7, 8 (latest release in each stream)
- **HA Configuration**: Deploys 3 MONs and 3 MGRs (when 3+ hosts available)
- **Automatic OSD Deployment**: Uses cephadm's `--all-available-devices` (optional)
- **Dashboard & Monitoring**: Full monitoring stack with Prometheus, Grafana, Alertmanager

## Container Image Mapping

The script automatically selects the correct container image based on your Ceph major version and RHEL version. Using `:latest` tag pulls the most recent release in that major version stream.

| Ceph Version | RHEL 9 Image | RHEL 8 Image | Notes |
|-------------|--------------|--------------|-------|
| **8** | `cp.icr.io/cp/ibm-ceph/ceph-8-rhel9:latest` | N/A | |
| **7** | `cp.icr.io/cp/ibm-ceph/ceph-7-rhel9:latest` | `cp.icr.io/cp/ibm-ceph/ceph-7-rhel8:latest` | |
| **6** | `cp.icr.io/cp/ibm-ceph/ceph-6-rhel9:latest` | `cp.icr.io/cp/ibm-ceph/ceph-6-rhel8:latest` | |
| **5** | `cp.icr.io/cp/ibm-ceph/ceph-5-rhel8:latest` | `cp.icr.io/cp/ibm-ceph/ceph-5-rhel8:latest` | RHEL 8 image used for both |

## Version Compatibility Matrix

| Ceph Version | RHEL 9 Supported | RHEL 8 Supported | Notes |
|-------------|------------------|------------------|-------|
| **8** | 9.4, 9.5, 9.6 | ❌ | Latest GA |
| **7** | 9.2 - 9.6 | 8.7, 8.8, 8.10* | |
| **6** | 9.2 - 9.5 | 8.8 - 8.10* | |
| **5** | 9.0 - 9.2 | 8.6 - 8.8 | |

*RHEL 8 deployments require RHEL 9 bootstrap node for versions 6 and 7

## Prerequisites

1. **RHEL Subscription**: All nodes must be registered with Red Hat
2. **IBM Entitlement Key**: Obtain from [MyIBM Container Library](https://myibm.ibm.com/products-services/containerlibrary)
3. **Network Connectivity**: All nodes must be reachable from the admin workstation
4. **Root Access**: Script requires root privileges on all nodes

## Installation

```bash
# Make the script executable
chmod +x ibm_ceph_deploy.py

# Verify Python 3 is available
python3 --version
```

## Usage

### Basic Deployment

```bash
./ibm_ceph_deploy.py \
  --inventory hosts_inventory.txt \
  --ceph-version 7 \
  --entitlement-key <YOUR_IBM_ENTITLEMENT_KEY>
```

### With SSH Setup

If SSH passwordless isn't configured yet:

```bash
./ibm_ceph_deploy.py \
  --inventory hosts_inventory.txt \
  --ceph-version 8 \
  --entitlement-key <YOUR_IBM_ENTITLEMENT_KEY> \
  --setup-ssh \
  --ssh-password <CURRENT_ROOT_PASSWORD>
```

### With Cluster Network

For dedicated cluster traffic (replication, recovery):

```bash
./ibm_ceph_deploy.py \
  --inventory hosts_inventory.txt \
  --ceph-version 7 \
  --entitlement-key <YOUR_IBM_ENTITLEMENT_KEY> \
  --cluster-network 10.10.0.0/24
```

### Skip OSD Deployment

Deploy cluster without OSDs (configure manually later):

```bash
./ibm_ceph_deploy.py \
  --inventory hosts_inventory.txt \
  --ceph-version 7 \
  --entitlement-key <YOUR_IBM_ENTITLEMENT_KEY> \
  --skip-osd
```

## Inventory File Format

Create a text file with one host per line. The **first host** is the bootstrap node.

### Simple Format
```
ceph-node1
ceph-node2
ceph-node3
```

### With IP Addresses
```
ceph-node1,192.168.1.101
ceph-node2,192.168.1.102
ceph-node3,192.168.1.103
```

### JSON Format
```json
[
  {"hostname": "ceph-node1", "ip": "192.168.1.101"},
  {"hostname": "ceph-node2", "ip": "192.168.1.102"},
  {"hostname": "ceph-node3", "ip": "192.168.1.103"}
]
```

## Command Line Options

| Option | Required | Description |
|--------|----------|-------------|
| `--inventory, -i` | Yes | Path to hosts inventory file |
| `--ceph-version, -v` | Yes | IBM Storage Ceph major version (5, 6, 7, 8) - deploys latest in that stream |
| `--entitlement-key, -k` | Yes | IBM entitlement key for container registry |
| `--setup-ssh` | No | Configure SSH passwordless authentication |
| `--ssh-password` | No* | Root password for SSH setup (*required with --setup-ssh) |
| `--cluster-network` | No | Cluster network CIDR (e.g., 10.10.0.0/24) |
| `--skip-osd` | No | Skip automatic OSD deployment |
| `--skip-firewall` | No | Skip firewall configuration |
| `--force` | No | Continue with unsupported OS version (not recommended) |

## Deployment Workflow

The script performs these steps in order:

1. **Parse Inventory** - Load and validate host list
2. **SSH Setup** (optional) - Configure passwordless SSH for root
3. **OS Validation** - Check RHEL version compatibility (use `--force` to bypass)
4. **Repository Config** - Add IBM Storage Ceph repos on all nodes (parallel, skips if exists)
5. **Package Install** - Install cephadm, podman, lvm2, license (parallel, skips if installed)
6. **Firewall Config** - Open required Ceph ports (parallel)
7. **Registry Login** - Authenticate to cp.icr.io on all nodes (parallel)
8. **Bootstrap** - Initialize cluster with cephadm bootstrap
9. **Cluster Expansion** - Add remaining hosts, configure 3 MONs/MGRs
10. **OSD Deployment** (optional) - Deploy OSDs on all available devices
11. **Summary** - Display cluster status and dashboard credentials

## Performance Optimizations

The script includes several optimizations for faster deployments:

- **Parallel Execution**: Repository configuration, package installation, firewall setup, and registry login run in parallel across all hosts (up to 5 concurrent operations)
- **Skip-if-Exists**: Repositories and packages are checked before installation - already configured/installed items are skipped
- **Idempotent Operations**: Safe to re-run if a deployment is interrupted

## Post-Deployment

### Access Dashboard

The script outputs the dashboard URL and credentials:
```
Dashboard URL:    https://192.168.1.101:8443/
Dashboard User:   admin
Dashboard Pass:   <generated_password>
```

### Manual OSD Configuration

If you used `--skip-osd`, deploy OSDs manually:

```bash
# List available devices
cephadm shell -- ceph orch device ls --wide

# Deploy on all available devices
cephadm shell -- ceph orch apply osd --all-available-devices

# Or use a drive group spec for selective deployment
cephadm shell -- ceph orch apply osd -i osd_spec.yml
```

### Useful Commands

```bash
# Cluster status
cephadm shell -- ceph -s

# OSD tree
cephadm shell -- ceph osd tree

# Service status
cephadm shell -- ceph orch ls

# Host status
cephadm shell -- ceph orch host ls

# Health details
cephadm shell -- ceph health detail
```

## Troubleshooting

### SSH Connection Failed
- Verify hostname resolution: `getent hosts <hostname>`
- Check SSH connectivity: `ssh root@<hostname>`
- Ensure root login is permitted in `/etc/ssh/sshd_config`

### OS Compatibility Error
- The script validates RHEL versions against IBM's support matrix
- Ensure all nodes run a supported RHEL version
- For RHEL 8 clusters (Ceph 6.x/7.x), bootstrap node must be RHEL 9

### Repository Issues
- Verify RHEL subscription: `subscription-manager status`
- Check repo availability: `dnf repolist`

### Registry Authentication Failed
- Verify entitlement key at [MyIBM](https://myibm.ibm.com/products-services/containerlibrary)
- Test manually: `podman login cp.icr.io -u cp -p <key>`

### Bootstrap Failures
- Check `/var/log/ceph/cephadm.log` on the bootstrap node
- Ensure time is synchronized: `chronyc tracking`
- Verify network connectivity between nodes

## License

This tool is provided as-is for automating IBM Storage Ceph deployments.
IBM Storage Ceph requires a valid IBM license and entitlement.