import argparse
import ctypes
import ipaddress
import json
import logging
import sys
from collections import Counter
from pathlib import Path

import pydivert

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}  # 58 = ICMPv6


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _as_list(value):
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


class Rule:
    """One rule from rules.json. Missing fields mean 'match anything'."""

    def __init__(self, data: dict):
        self.name = data.get("name", "unnamed")
        self.action = data.get("action", "block").lower()
        self.direction = data.get("direction", "any").lower()  # in | out | any
        self.protocol = data.get("protocol", "any").lower()    # tcp | udp | icmp | any

        ips = _as_list(data.get("remote_ip"))
        self.remote_ips = [ipaddress.ip_network(i, strict=False) for i in ips] if ips else None

        rports = _as_list(data.get("remote_port"))
        self.remote_ports = {int(p) for p in rports} if rports else None

        lports = _as_list(data.get("local_port"))
        self.local_ports = {int(p) for p in lports} if lports else None

    def matches(self, info: dict) -> bool:
        if self.direction != "any" and self.direction != info["direction"]:
            return False
        if self.protocol != "any" and self.protocol != info["proto"]:
            return False
        if self.remote_ips is not None:
            try:
                ip = ipaddress.ip_address(info["remote_ip"])
            except ValueError:
                return False
            if not any(ip in net for net in self.remote_ips):
                return False
        if self.remote_ports is not None and info["remote_port"] not in self.remote_ports:
            return False
        if self.local_ports is not None and info["local_port"] not in self.local_ports:
            return False
        return True


class RuleEngine:
    def __init__(self, path: Path):
        config = json.loads(path.read_text(encoding="utf-8"))
        self.default_action = config.get("default_action", "allow").lower()
        self.rules = [Rule(r) for r in config.get("rules", [])]

    def decide(self, info: dict):
        for rule in self.rules:
            if rule.matches(info):
                return rule.action, rule.name
        return self.default_action, "default policy"


def describe(packet) -> dict:
    """Turn a raw packet into a simple dict that rules can be matched against."""
    proto_num = packet.protocol[0]
    outbound = packet.is_outbound
    if outbound:
        local_ip, local_port = packet.src_addr, packet.src_port
        remote_ip, remote_port = packet.dst_addr, packet.dst_port
    else:
        local_ip, local_port = packet.dst_addr, packet.dst_port
        remote_ip, remote_port = packet.src_addr, packet.src_port
    return {
        "direction": "out" if outbound else "in",
        "proto": PROTO_NAMES.get(proto_num, str(proto_num)),
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "size": len(packet.raw),
    }


def fmt(info: dict) -> str:
    arrow = "->" if info["direction"] == "out" else "<-"
    return (f"{info['proto'].upper():5} {info['direction'].upper():3} "
            f"{info['local_ip']}:{info['local_port']} {arrow} "
            f"{info['remote_ip']}:{info['remote_port']} ({info['size']}B)")


def setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.FileHandler("firewall.log", encoding="utf-8"),
                  logging.StreamHandler(sys.stdout)],
    )


def main():
    parser = argparse.ArgumentParser(description="Personal Firewall (Windows)")
    parser.add_argument("--rules", default="rules.json", help="path to rules file")
    parser.add_argument("--monitor", action="store_true",
                        help="log what WOULD be blocked but allow everything")
    parser.add_argument("--verbose", action="store_true", help="log allowed packets too")
    args = parser.parse_args()

    if sys.platform != "win32":
        sys.exit("This version targets Windows (WinDivert).")
    if not is_admin():
        sys.exit("Please run this from an Administrator terminal.")

    setup_logging(args.verbose)
    engine = RuleEngine(Path(args.rules))
    stats = Counter()
    mode = "MONITOR (no dropping)" if args.monitor else "ENFORCING"
    logging.info("Firewall started - %s - %d rules, default=%s",
                 mode, len(engine.rules), engine.default_action)
    logging.info("Press Ctrl+C to stop. Traffic returns to normal when stopped.")

    try:
        with pydivert.WinDivert("true") as divert:
            for packet in divert:
                # never touch loopback traffic (127.0.0.1 / ::1)
                if packet.src_addr in ("127.0.0.1", "::1") and packet.dst_addr in ("127.0.0.1", "::1"):
                    divert.send(packet)
                    continue

                info = describe(packet)
                action, rule_name = engine.decide(info)
                stats[f"{info['proto']}_{action}"] += 1

                if action == "block":
                    logging.warning("BLOCK [%s] %s", rule_name, fmt(info))
                    if args.monitor:
                        divert.send(packet)      # monitor mode: let it through anyway
                    # enforcing mode: simply not re-injecting = packet dropped
                else:
                    logging.debug("ALLOW [%s] %s", rule_name, fmt(info))
                    divert.send(packet)
    except KeyboardInterrupt:
        pass
    finally:
        logging.info("Stopped. Summary:")
        for key, count in sorted(stats.items()):
            logging.info("  %-14s %d", key, count)


if __name__ == "__main__":
    main()
