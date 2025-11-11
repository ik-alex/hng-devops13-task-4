# Mini-VPC Manager(vpcctl.py)

A lightweight Virtual Private Cloud (VPC) manager for Linux using network namespaces, veth pairs, bridges, NAT, and iptables.
All actions are logged and resources can be cleaned up using the cleanup script.

## Features

- Create VPCs with a specific CIDR.

- Add subnets to VPCs with automatic gateway assignment.

- Deploy HTTP servers in subnets for testing connectivity.

- Enable NAT for internet access via a host interface.

- Peer VPCs and optionally allow specific IP ranges.

- Apply network policies (ingress rules) to subnets.

- List and show VPC configurations.

- Cleanup all VPCs, subnets, bridges, veths, and iptables rules with a single command.

- Full logging of all operations (vpcctl.log).

## Requirements

- Linux system (tested on Ubuntu).

- Python 3.10+

- Root privileges to create namespaces, bridges, and modify iptables.

- Standard Linux networking utilities: `ip`, `iptables`, `grep`.

## Installation

1. Clone or copy the repository to your Linux machine.

2. Make scripts executable:

```bash
chmod +x vpcctl.py vpc_cleanup.py
```

3. Ensure Python 3 is installed:

```bash
python3 --version
```

## Usage

All commands require root privileges:

```bash
sudo ./vpcctl.py <command> [options]
```

1. Create a VPC

```bash
sudo ./vpcctl.py create-vpc myvpc --cidr 10.42.0.0/16

```

2. Add a Subnet

```bash
sudo ./vpcctl.py add-subnet myvpc public 10.42.1.0/24 --gw-ip 10.42.1.1

```

3. Enable NAT

```bash
sudo ./vpcctl.py enable-nat myvpc --subnet public --iface eth0

```

4. Deploy an HTTP Server

```bash
sudo ./vpcctl.py deploy-server myvpc public --port 8080
```

5. Peer VPCs

```bash
sudo ./vpcctl.py peer myvpc vpc2 --allow 10.42.1.2:10.43.1.2
```

6. Apply Network Policy

```bash
sudo ./vpcctl.py apply-policy policy.json
```

Sample policy.json:

```bash
[
  {
    "subnet": "10.42.1.0/24",
    "ingress": [
      {"port": 80, "protocol": "tcp", "action": "ALLOW"},
      {"port": 22, "protocol": "tcp", "action": "DROP"}
    ]
  }
]
```

7. List VPCs

```bash
sudo ./vpcctl.py list
```

8. Show VPC Details

```bash
sudo ./vpcctl.py show myvpc
```

9. Delete a VPC

```
sudo ./vpcctl.py delete-vpc myvpc

```

## Cleanup

To remove all VPCs, subnets, bridges, veths, and iptables rules, run:

```
sudo ./vpcctl_cleanup.py
```

Logs for cleanup are saved in `vpcctl_cleanup.log`.

## Logging

All operations are logged in `vpcctl.log` for debugging and auditing.
Cleanup actions are logged in `vpcctl_cleanup.log`.

## Notes

- Scripts are idempotent: running the same command multiple times will not break the environment.

- All commands require root access.

- Designed for learning and testing networking concepts in Linux.

## Author

Ikenna Alexander Nwajagu
# hng-devops13-task-4
