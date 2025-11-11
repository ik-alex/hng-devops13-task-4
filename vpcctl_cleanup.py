#!/usr/bin/env python3
"""
vpc_cleanup.py - Fully cleans up all VPCs, subnets, bridges, veths, namespaces, NAT, and iptables rules
"""

import json, os, shlex, subprocess, sys
from pathlib import Path
from datetime import datetime

STATE_PATH = Path.cwd() / "vpcctl_state.json"
LOG_PATH = Path.cwd() / "vpcctl_cleanup.log"

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
    return res.stdout.strip()

def exists_link(name):
    return subprocess.run(f"ip link show {shlex.quote(name)}", shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def exists_netns(ns):
    return subprocess.run(f"ip netns list | grep -w {shlex.quote(ns)}", shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def ensure_root():
    if os.geteuid() != 0:
        log("Must be run as root")
        sys.exit(1)

# -------------------- cleanup --------------------

def cleanup_vpcs():
    ensure_root()
    if not STATE_PATH.exists():
        log("No state file found; nothing to clean")
        return

    state = json.loads(STATE_PATH.read_text())

    # Delete peers first
    for peer in state.get("peers", []):
        for link in ["pair_a", "pair_b"]:
            if exists_link(peer[link]):
                run(f"ip link delete {peer[link]}")
        log(f"Deleted peer veths between {peer['vpc_a']} and {peer['vpc_b']}")

    # Delete subnets and namespaces
    for vpc_name, vpc in state.get("vpcs", {}).items():
        for subnet_name, subnet in vpc.get("subnets", {}).items():
            ns = subnet["ns"]
            veth_br = subnet["veth_br"]
            if exists_netns(ns):
                run(f"ip netns delete {ns}")
                log(f"Deleted namespace {ns}")
            if exists_link(veth_br):
                run(f"ip link delete {veth_br}")
                log(f"Deleted veth {veth_br}")

    # Delete bridges
    for vpc_name, vpc in state.get("vpcs", {}).items():
        bridge = vpc["bridge"]
        if exists_link(bridge):
            run(f"ip link set {bridge} down")
            run(f"ip link delete {bridge}")
            log(f"Deleted bridge {bridge}")

    # Clear iptables NAT/forward rules (best-effort)
    run("iptables -F")
    run("iptables -t nat -F")
    run("iptables -X")
    run("iptables -t nat -X")
    log("Flushed all iptables rules")

    # Remove state file
    try:
        STATE_PATH.unlink()
        log("Deleted state file")
    except FileNotFoundError:
        pass

    log("VPC cleanup completed!")

# -------------------- main --------------------

if __name__ == "__main__":
    cleanup_vpcs()
