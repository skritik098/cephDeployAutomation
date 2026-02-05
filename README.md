# IBM Storage Ceph Deployment Tool

Single-script deployment tool for IBM Storage Ceph clusters using cephadm.

## Features

- **OS-aware version listing**: Shows compatible versions for your OS
- **SSH setup**: Automated key generation and distribution  
- **Flexible topology**: MON/MGR/OSD placement via labels
- **OSD options**: Auto-deploy all devices or skip for manual config

## Requirements

- Python 3.9+ with PyYAML (`pip install pyyaml`)
- Target nodes: RHEL/Rocky/AlmaLinux 8.x or 9.x
- IBM Entitlement Key from https://myibm.ibm.com/products-services/containerlibrary
- (Optional) `sshpass` for automated SSH key distribution

## Quick Start

```bash
# 1. Check compatible versions for your OS
./deploy_ceph.py list-versions

# 2. Generate hosts file
./deploy_ceph.py generate-hosts --nodes 3 -o hosts.yml
# Edit hosts.yml with your IPs

# 3. Setup SSH access
./deploy_ceph.py setup-ssh --hosts hosts.yml --prompt-password

# 4. Deploy cluster
./deploy_ceph.py deploy --hosts hosts.yml --version 8.0 --registry-password <KEY>
```

## Commands

```bash
# List versions with OS compatibility check
./deploy_ceph.py list-versions

# Setup SSH keys (generates + distributes)
./deploy_ceph.py setup-ssh --hosts hosts.yml --prompt-password

# Run preflight checks
./deploy_ceph.py preflight --version 8.0 --prepare

# Deploy cluster
./deploy_ceph.py deploy --hosts hosts.yml --version 8.0 --registry-password <KEY>

# Deploy without OSDs
./deploy_ceph.py deploy --hosts hosts.yml --version 7.1 --skip-osd --registry-password <KEY>

# Check cluster status
./deploy_ceph.py status
```

## Environment Variable

```bash
export IBM_ENTITLEMENT_KEY="your-key-here"
```

## Hosts File Format

```yaml
# Simple format with labels
- hostname: ceph-node1
  addr: 192.168.1.11
  labels: [mon, mgr, osd]

- hostname: ceph-node2
  addr: 192.168.1.12
  labels: [mon, mgr, osd]

- hostname: ceph-node3
  addr: 192.168.1.13
  labels: [mon, osd]
  osd_devices:        # Optional: specific devices
    - /dev/sdb
    - /dev/sdc
```

Labels determine service placement:
- `mon` - Monitor (3 or 5 recommended)
- `mgr` - Manager (2-3 for HA)
- `osd` - Storage nodes

## Supported Versions

| IBM Ceph | Upstream | RHEL Support |
|----------|----------|--------------|
| 8.0 | Squid 19.x | 9.4, 9.5, 9.6 |
| 7.1 | Reef 18.x | 8.8-8.10, 9.2, 9.4 |
| 7.0 | Reef 18.x | 8.6-8.8, 9.0, 9.2 |
| 6.1 | Quincy 17.x | 8.4-8.8, 9.0, 9.2 |

## Workflow

1. **list-versions** - See what's compatible with your OS
2. **generate-hosts** - Create hosts.yml template
3. **setup-ssh** - Configure passwordless SSH
4. **preflight** - Check/prepare nodes
5. **deploy** - Bootstrap and configure cluster
6. **status** - Verify deployment

## License

Apache 2.0
