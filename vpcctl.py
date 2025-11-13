#!/usr/bin/env python3
"""
vpcctl.py - Mini-VPC manager on Linux using namespaces, veth pairs, bridges, NAT, and iptables
Logs all actions to vpcctl.log
"""

import argparse, json, os, shlex, subprocess, sys, ipaddress
from pathlib import Path
from datetime import datetime

STATE_PATH = Path.cwd() / "vpcctl_state.json"
LOG_PATH = Path.cwd() / "vpcctl.log"

# -------------------- logging --------------------

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")

# -------------------- utilities --------------------

def run(cmd):
    log(f"Running: {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        log(f"Command failed (rc={res.returncode}): {res.stderr.strip()}")
        raise RuntimeError(f"Command failed: {cmd}")
    return res.stdout.strip()

def exists_link(name):
    return subprocess.run(f"ip link show {shlex.quote(name)}", shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def exists_netns(ns):
    return subprocess.run(f"ip netns list | grep -w {shlex.quote(ns)}", shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def load_state():
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"vpcs": {}, "peers": []}

def save_state(s):
    STATE_PATH.write_text(json.dumps(s, indent=2))

def ensure_root():
    if os.geteuid() != 0:
        log("vpcctl: must be run as root")
        sys.exit(1)

def short_ifname(*parts, max_len=15):
    name = '-'.join(parts)
    if len(name) <= max_len:
        return name
    total_len = sum(len(p) for p in parts)
    chars_left = max_len - (len(parts)-1)
    truncated_parts = []
    for p in parts:
        part_len = max(1, int(len(p)/total_len * chars_left))
        truncated_parts.append(p[:part_len])
    return '-'.join(truncated_parts)

# -------------------- core operations --------------------

def create_vpc(args):
    state = load_state()
    name = args.name
    cidr = args.cidr
    try:
        net = ipaddress.ip_network(cidr)
    except Exception as e:
        raise SystemExit(f"Invalid CIDR: {e}")
    for vname, v in state["vpcs"].items():
        if net.overlaps(ipaddress.ip_network(v["cidr"])):
            raise SystemExit(f"CIDR {cidr} overlaps with existing VPC {vname} ({v['cidr']})")
    if name in state["vpcs"]:
        log(f"VPC {name} already exists; skipping")
        return
    bridge = f"br-{name}"
    if not exists_link(bridge):
        run(f"ip link add name {bridge} type bridge")
        run(f"ip link set {bridge} up")
    state["vpcs"][name] = {"cidr": cidr, "bridge": bridge, "subnets": {}}
    save_state(state)
    log(f"Created VPC {name} with bridge {bridge} CIDR {cidr}")

def add_subnet(args):
    state = load_state()
    vpc = args.vpc
    if vpc not in state["vpcs"]:
        raise SystemExit("VPC not found")
    sname, scidr, gw_ip = args.name, args.cidr, args.gw_ip
    snet = ipaddress.ip_network(scidr)
    if sname in state["vpcs"][vpc]["subnets"]:
        log(f"Subnet {sname} already exists; skipping")
        return
    bridge = state["vpcs"][vpc]["bridge"]
    ns = short_ifname(vpc, sname, "ns")
    veth_ns = short_ifname("v", vpc, sname)
    veth_br = short_ifname(veth_ns, "br")
    if not exists_netns(ns):
        run(f"ip netns add {ns}")
    if not exists_link(veth_ns):
        run(f"ip link add {veth_ns} type veth peer name {veth_br}")
    run(f"ip link set {veth_ns} netns {ns}")
    run(f"ip link set {veth_br} master {bridge}")
    run(f"ip link set {veth_br} up")
    hosts = list(snet.hosts())
    if len(hosts) < 2:
        raise SystemExit("Subnet too small")
    gateway = gw_ip or str(hosts[0])
    ns_ip = str(hosts[1])
    run(f"ip netns exec {ns} ip addr add {ns_ip}/{snet.prefixlen} dev {veth_ns}")
    run(f"ip netns exec {ns} ip link set {veth_ns} up")
    run(f"ip netns exec {ns} ip link set lo up")
    if subprocess.run(f"ip addr show dev {bridge} | grep -w {gateway}", shell=True).returncode != 0:
        run(f"ip addr add {gateway}/{snet.prefixlen} dev {bridge}")
    run(f"ip netns exec {ns} ip route add default via {gateway}")
    state["vpcs"][vpc]["subnets"][sname] = {"cidr": scidr, "ns": ns,
                                           "veth_ns": veth_ns, "veth_br": veth_br,
                                           "gw": gateway, "addr": ns_ip}
    save_state(state)
    log(f"Added subnet {sname} ns={ns} ip={ns_ip} gw={gateway}")

def enable_nat(args):
    state = load_state()
    vpc, subnet, iface = args.vpc, args.subnet, args.iface
    if vpc not in state["vpcs"] or subnet not in state["vpcs"][vpc]["subnets"]:
        raise SystemExit("VPC/subnet not found")
    cidr = state["vpcs"][vpc]["subnets"][subnet]["cidr"]
    run(f"iptables -t nat -A POSTROUTING -s {cidr} -o {iface} -j MASQUERADE")
    run(f"iptables -A FORWARD -s {cidr} -o {iface} -j ACCEPT")
    run(f"iptables -A FORWARD -d {cidr} -i {iface} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    log(f"NAT enabled for {vpc}/{subnet} via {iface}")

def deploy_server(args):
    state = load_state()
    vpc, subnet, port = args.vpc, args.subnet, args.port
    if vpc not in state["vpcs"] or subnet not in state["vpcs"][vpc]["subnets"]:
        raise SystemExit("VPC/subnet not found")
    ns = state["vpcs"][vpc]["subnets"][subnet]["ns"]
    run(f"ip netns exec {ns} nohup python3 -m http.server {port} >/tmp/vpcctl-{ns}-{port}.log 2>&1 &")
    log(f"Deployed http.server in {ns} on port {port}")

# def peer_vpcs(args):
#     state = load_state()
#     a, b, allow = args.vpc_a, args.vpc_b, args.allow
#     if a not in state["vpcs"] or b not in state["vpcs"]:
#         raise SystemExit("Both VPCs must exist")
#     pair_a = short_ifname("peer", a, b, "a")
#     pair_b = short_ifname("peer", a, b, "b")
#     if not exists_link(pair_a):
#         run(f"ip link add {pair_a} type veth peer name {pair_b}")
#     run(f"ip link set {pair_a} master {state['vpcs'][a]['bridge']}")
#     run(f"ip link set {pair_b} master {state['vpcs'][b]['bridge']}")
#     run(f"ip link set {pair_a} up")
#     run(f"ip link set {pair_b} up")
#     state["peers"].append({"vpc_a": a, "vpc_b": b, "pair_a": pair_a, "pair_b": pair_b, "allow": allow})
#     save_state(state)
#     if allow:
#         for p in allow.split(','):
#             left, right = p.split(':')
#             run(f"iptables -A FORWARD -s {left} -d {right} -j ACCEPT")
#             run(f"iptables -A FORWARD -s {right} -d {left} -j ACCEPT")
#         va, vb = state['vpcs'][a]['cidr'], state['vpcs'][b]['cidr']
#         run(f"iptables -A FORWARD -s {va} -d {vb} -j DROP")
#         run(f"iptables -A FORWARD -s {vb} -d {va} -j DROP")
#     log(f"Peered {a} <-> {b} allow={allow}")

def peer_vpcs(args):
    state = load_state()
    a, b, allow = args.vpc_a, args.vpc_b, args.allow
    if a not in state["vpcs"] or b not in state["vpcs"]:
        raise SystemExit("Both VPCs must exist")

    router_ns = short_ifname("peer", a, b, "rns")
    # names
    ra_ns = short_ifname("r", a)
    ra_br = short_ifname("r", a, "br")
    rb_ns = short_ifname("r", b)
    rb_br = short_ifname("r", b, "br")

    # create namespace if not exists
    if not exists_netns(router_ns):
        run(f"ip netns add {router_ns}")

    # create veth pairs (router-side and bridge-side)
    if not exists_link(ra_ns):
        run(f"ip link add {ra_ns} type veth peer name {ra_br}")
    if not exists_link(rb_ns):
        run(f"ip link add {rb_ns} type veth peer name {rb_br}")

    # attach bridge-side ends to each VPC bridge and bring up
    run(f"ip link set {ra_br} master {state['vpcs'][a]['bridge']}")
    run(f"ip link set {rb_br} master {state['vpcs'][b]['bridge']}")
    run(f"ip link set {ra_br} up")
    run(f"ip link set {rb_br} up")

    # move router-side ends into router namespace
    run(f"ip link set {ra_ns} netns {router_ns}")
    run(f"ip link set {rb_ns} netns {router_ns}")

    # compute router IPs — pick .254 in each public subnet (should be free)
    cidr_a = ipaddress.ip_network(state['vpcs'][a]['cidr'])
    cidr_b = ipaddress.ip_network(state['vpcs'][b]['cidr'])
    # we need IPs in the specific *subnet* used for peering (use public subnet gw's network)
    # find a public subnet entry in each VPC
    def find_public_subnet(v):
        for sname, s in state['vpcs'][v]['subnets'].items():
            return ipaddress.ip_network(s['cidr'])
        raise SystemExit(f"No subnet found in VPC {v}")

    net_a = find_public_subnet(a)
    net_b = find_public_subnet(b)

    router_ip_a = str(list(net_a.hosts())[-1])  # .254-ish
    router_ip_b = str(list(net_b.hosts())[-1])

    # configure router namespace interfaces
    run(f"ip netns exec {router_ns} ip addr add {router_ip_a}/{net_a.prefixlen} dev {ra_ns}")
    run(f"ip netns exec {router_ns} ip link set {ra_ns} up")
    run(f"ip netns exec {router_ns} ip addr add {router_ip_b}/{net_b.prefixlen} dev {rb_ns}")
    run(f"ip netns exec {router_ns} ip link set {rb_ns} up")
    run(f"ip netns exec {router_ns} ip link set lo up")

    # enable ip forwarding inside router namespace
    run(f"ip netns exec {router_ns} sysctl -w net.ipv4.ip_forward=1")

    # add host routes: route traffic for VPC-A via router_ip_a and VPC-B via router_ip_b
    # (This ensures the host knows to route between them via the router)
    run(f"ip route add {state['vpcs'][a]['cidr']} via {router_ip_a} dev {ra_br} || true")
    run(f"ip route add {state['vpcs'][b]['cidr']} via {router_ip_b} dev {rb_br} || true")

    # Allow forwarding in host iptables between those CIDRs (and any explicit allow rules)
    run(f"iptables -A FORWARD -s {state['vpcs'][a]['cidr']} -d {state['vpcs'][b]['cidr']} -j ACCEPT || true")
    run(f"iptables -A FORWARD -s {state['vpcs'][b]['cidr']} -d {state['vpcs'][a]['cidr']} -j ACCEPT || true")

    state["peers"].append({"vpc_a": a, "vpc_b": b, "router_ns": router_ns,
                          "ra_ns": ra_ns, "ra_br": ra_br, "rb_ns": rb_ns, "rb_br": rb_br, "allow": allow})
    save_state(state)
    log(f"Peered {a} <-> {b} via router ns {router_ns} (ra={router_ip_a}, rb={router_ip_b})")


def apply_policy(args):
    state = load_state()
    path = Path(args.file)
    if not path.exists():
        raise SystemExit("Policy file not found")
    policies = json.loads(path.read_text())
    for pol in policies:
        subnet, ingress = pol.get('subnet'), pol.get('ingress', [])
        for v in state['vpcs'].values():
            for s in v['subnets'].values():
                if ipaddress.ip_network(subnet) == ipaddress.ip_network(s['cidr']):
                    ns = s['ns']
                    run(f"ip netns exec {ns} iptables -F INPUT || true")
                    run(f"ip netns exec {ns} iptables -F FORWARD || true")
                    for rule in ingress:
                        port, proto, action = rule['port'], rule['protocol'], rule['action'].upper()
                        act = 'ACCEPT' if action == 'ALLOW' else 'DROP'
                        run(f"ip netns exec {ns} iptables -A INPUT -p {proto} --dport {port} -j {act}")
                        run(f"ip netns exec {ns} iptables -A FORWARD -p {proto} --dport {port} -j {act}")
                    log(f"Applied policy to ns={ns}: {ingress}")

def delete_vpc(args):
    state = load_state()
    name = args.name
    if name not in state['vpcs']:
        log("VPC not found; nothing to delete")
        return
    v = state['vpcs'][name]
    bridge = v['bridge']
    for s in v['subnets'].values():
        ns, veth_br = s['ns'], s['veth_br']
        if exists_netns(ns):
            run(f"ip netns delete {ns}")
        if exists_link(veth_br):
            run(f"ip link delete {veth_br}")
    if exists_link(bridge):
        run(f"ip link set {bridge} down")
        run(f"ip link delete {bridge}")
    state['vpcs'].pop(name)
    save_state(state)
    log(f"Deleted VPC {name}")

def list_vpcs(args):
    state = load_state()
    for name, v in state['vpcs'].items():
        log(f"- {name}: CIDR={v['cidr']} bridge={v['bridge']} subnets={list(v['subnets'].keys())}")

def show_vpc(args):
    state = load_state()
    name = args.name
    log(json.dumps(state['vpcs'].get(name, "not found"), indent=2))

# -------------------- CLI --------------------

def main():
    ensure_root()
    p = argparse.ArgumentParser(prog='vpcctl')
    sub = p.add_subparsers(dest='cmd')

    pc = sub.add_parser('create-vpc')
    pc.add_argument('name')
    pc.add_argument('--cidr', required=True)

    ps = sub.add_parser('add-subnet')
    ps.add_argument('vpc')
    ps.add_argument('name')
    ps.add_argument('cidr')
    ps.add_argument('--gw-ip', default=None)

    pn = sub.add_parser('enable-nat')
    pn.add_argument('vpc')
    pn.add_argument('--subnet', required=True)
    pn.add_argument('--iface', required=True)

    pd = sub.add_parser('deploy-server')
    pd.add_argument('vpc')
    pd.add_argument('subnet')
    pd.add_argument('--port', type=int, default=8000)

    pp = sub.add_parser('peer')
    pp.add_argument('vpc_a')
    pp.add_argument('vpc_b')
    pp.add_argument('--allow', default=None)

    pa = sub.add_parser('apply-policy')
    pa.add_argument('file')

    pdel = sub.add_parser('delete-vpc')
    pdel.add_argument('name')

    pl = sub.add_parser('list')
    ps_show = sub.add_parser('show')
    ps_show.add_argument('name')

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(0)

    cmds = {
        'create-vpc': create_vpc,
        'add-subnet': add_subnet,
        'enable-nat': enable_nat,
        'deploy-server': deploy_server,
        'peer': peer_vpcs,
        'apply-policy': apply_policy,
        'delete-vpc': delete_vpc,
        'list': list_vpcs,
        'show': show_vpc
    }

    try:
        cmds[args.cmd](args)
    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
