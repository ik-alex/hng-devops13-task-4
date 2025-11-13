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

```bash
git clone https://github.com/ik-alex/HNG-13-DevOps.git
cd HNG-13-DevOps/stage-4
chmod +x vpcctl.py vpcctl_cleanup.py
```

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

1. Create two VPC

```bash
sudo python3 ./vpcctl.py create-vpc vpc1 --cidr 10.42.0.0/16
sudo python3 ./vpcctl.py create-vpc vpc2 --cidr 10.43.0.0/16

```

2. Add a Subnet

```bash
sudo python3 ./vpcctl.py add-subnet vpc1 public 10.42.1.0/24 --gw-ip 10.42.1.1
sudo python3 ./vpcctl.py add-subnet vpc1 private 10.42.2.0/24 --gw-ip 10.42.2.1
sudo python3 ./vpcctl.py add-subnet vpc2 public 10.43.1.0/24 --gw-ip 10.43.1.1
sudo python3 ./vpcctl.py add-subnet vpc2 private 10.43.2.0/24 --gw-ip 10.43.2.1
```

3. Enable NAT

```bash
sudo python3 ./vpcctl.py enable-nat vpc1 --subnet public --iface eth0
sudo python3 ./vpcctl.py enable-nat vpc2 --subnet public --iface eth0
```

4. Deploy an HTTP Server

```bash
sudo python3 ./vpcctl.py deploy-server vpc1 public --port 8080
sudo python3 ./vpcctl.py deploy-server vpc2 public --port 8080
```

5. List Active VPCs

```bash
sudo python3 ./vpcctl.py list
```

6. Peer VPCs (Selective CIDR Peering)

```bash
sudo python3 ./vpcctl.py peer vpc1 vpc2 --allow 10.42.1.0/24:10.43.1.0/24
```

This allows selective communication only between `vpc1’s` public subnet and `vpc2’s` public subnet.

## Create a subnet-policy.json file:

```bash
cat <<EOF > subnet-policy.json
[
  {
    "subnet": "10.42.1.0/24",
    "ingress": [
      {"port": 8080, "protocol": "tcp", "action": "allow"},
      {"port": 22, "protocol": "tcp", "action": "deny"}
    ]
  },
  {
    "subnet": "10.43.1.0/24",
    "ingress": [
      {"port": 8080, "protocol": "tcp", "action": "allow"},
      {"port": 22, "protocol": "tcp", "action": "deny"}
    ]
  }
]
EOF

```

7. Apply Firewall Policies

```bash
sudo python3 ./vpcctl.py apply-policy subnet-policy.json

```

8. Connectivity Tests
   Within the same VPC:

```bash
sudo ip netns exec vpc1-public-ns curl http://10.42.1.2:8080  # Should work

```

Between VPCs (after peering):

```bash
sudo ip netns exec vpc1-public-ns curl http://10.43.1.2:8080  # Should work

```

Blocked by Policy:

```bash
sudo ip netns exec vpc1-public-ns nc -zv 10.42.1.2 22  # Should fail (blocked SSH)
```

9. Clean Up All Resources

When finished, remove all namespaces, bridges, veth pairs, and iptables rules:

```
sudo python3 ./vpcctl_cleanup.py
```

## Cleanup

To remove all VPCs, subnets, bridges, veths, and iptables rules, run:

```
sudo ./vpcctl_cleanup.py
```

Logs for cleanup are saved in `vpcctl_cleanup.log`.

If you encounter errors such as
`RTNETLINK answers: File exists` or `Device does not exist`,
it means leftover network namespaces or interfaces are still present from a previous run.

Use the following command to safely remove all VPC-related namespaces, bridges, and veth pairs before recreating them:

```bash
sudo bash -c '
for ns in $(ip netns list | awk "{print \$1}"); do
  echo "Deleting namespace $ns"
  ip netns delete $ns
done

for iface in $(ip link show | grep -E "vpc|pee|br-" | awk -F: "{print \$2}" | sed "s/@.*//" | tr -d " "); do
  echo "Deleting interface $iface"
  ip link delete $iface 2>/dev/null
done

echo "Cleanup complete!"
'
```

After running this script, verify cleanup:

```bash
ip netns list
ip link show | grep -E 'vpc|pee|br-'
```

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
