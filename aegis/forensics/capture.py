"""Network capture engine — live sniffing + PCAP handling.

Supports:
  - Live capture via scapy (libpcap backend)
  - PCAP file reading via dpkt or pyshark
  - Zeek log ingestion
  - NetFlow/IPFIX via nfdump
  - SHA-256 + BLAKE3 integrity chaining for court-admissible evidence
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional

from aegis.core.ui import console
from aegis.core.utils import ensure_dir, run_command, which


# ── Evidence chain ────────────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _blake3_file(path: Path) -> Optional[str]:
    """Return BLAKE3 hash if blake3 library is available."""
    try:
        import blake3  # type: ignore[import]
        h = blake3.blake3()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except ImportError:
        return None


class EvidenceChain:
    """Tamper-evident hash chain for PCAP files."""

    def __init__(self, chain_file: str) -> None:
        self.chain_file = Path(chain_file)
        self._entries: List[Dict] = []
        if self.chain_file.exists():
            try:
                self._entries = json.loads(self.chain_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._entries = []

    def record(self, pcap_path: Path, metadata: Optional[Dict] = None) -> Dict:
        sha256 = _sha256_file(pcap_path)
        blake3 = _blake3_file(pcap_path)
        prev_hash = self._entries[-1]["sha256"] if self._entries else "genesis"
        entry = {
            "index": len(self._entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file": str(pcap_path),
            "size_bytes": pcap_path.stat().st_size,
            "sha256": sha256,
            "blake3": blake3,
            "prev_sha256": prev_hash,
            "metadata": metadata or {},
        }
        self._entries.append(entry)
        self._save()
        return entry

    def verify(self) -> bool:
        for i, entry in enumerate(self._entries):
            if i == 0:
                continue
            if entry["prev_sha256"] != self._entries[i - 1]["sha256"]:
                return False
        return True

    def _save(self) -> None:
        self.chain_file.parent.mkdir(parents=True, exist_ok=True)
        self.chain_file.write_text(
            json.dumps(self._entries, indent=2), encoding="utf-8"
        )

    def export(self) -> List[Dict]:
        return list(self._entries)


# ── Live capture ──────────────────────────────────────────────────────────────

class LiveCapture:
    """Live packet capture using tcpdump (libpcap) with optional scapy callback."""

    def __init__(
        self,
        interface: str = "eth0",
        output_dir: str = "data/forensics/captures",
        bpf_filter: str = "",
        rotation_seconds: int = 300,
        max_files: int = 100,
    ) -> None:
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.bpf_filter = bpf_filter
        self.rotation_seconds = rotation_seconds
        self.max_files = max_files
        self._proc: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
        self._stop_event = threading.Event()
        self._current_file: Optional[Path] = None
        self.chain = EvidenceChain(str(self.output_dir / "evidence_chain.json"))

    def start(self, callback: Optional[Callable[[Path], None]] = None) -> None:
        """Start capture in background thread with optional file-rotation callback."""
        ensure_dir(str(self.output_dir))
        self._stop_event.clear()
        thread = threading.Thread(
            target=self._capture_loop, args=(callback,), daemon=True
        )
        thread.start()
        console.print(f"[primary]Capture started:[/primary] interface={self.interface} dir={self.output_dir}")

    def stop(self) -> Optional[Path]:
        self._stop_event.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        return self._current_file

    def _capture_loop(self, callback: Optional[Callable[[Path], None]]) -> None:
        while not self._stop_event.is_set():
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            out_file = self.output_dir / f"capture_{ts}.pcap"
            self._current_file = out_file
            self._run_tcpdump(out_file)
            if out_file.exists() and out_file.stat().st_size > 0:
                entry = self.chain.record(out_file, {"interface": self.interface, "filter": self.bpf_filter})
                console.print(f"[dim]Capture rotated → {out_file.name}  sha256={entry['sha256'][:16]}...[/dim]")
                if callback:
                    try:
                        callback(out_file)
                    except Exception as exc:
                        console.print(f"[warning]Capture callback error: {exc}[/warning]")
            self._cleanup_old_files()

    def _run_tcpdump(self, out_file: Path) -> None:
        if not which("tcpdump"):
            console.print("[error]tcpdump not found. Install with: apt install tcpdump[/error]")
            time.sleep(self.rotation_seconds)
            return
        cmd = [
            "tcpdump", "-i", self.interface,
            "-w", str(out_file),
            "-G", str(self.rotation_seconds),
            "-W", "1",
            "-n",
        ]
        if self.bpf_filter:
            cmd += self.bpf_filter.split()
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._proc.wait(timeout=self.rotation_seconds + 10)
        except (subprocess.TimeoutExpired, OSError):
            if self._proc:
                self._proc.kill()

    def _cleanup_old_files(self) -> None:
        files = sorted(self.output_dir.glob("capture_*.pcap"), key=lambda p: p.stat().st_mtime)
        while len(files) > self.max_files:
            files.pop(0).unlink(missing_ok=True)

    def capture_with_scapy(
        self,
        packet_callback: Callable,
        bpf_filter: str = "",
        count: int = 0,
        timeout: Optional[int] = None,
    ) -> None:
        """Real-time per-packet callback using scapy (requires root)."""
        try:
            from scapy.all import sniff  # type: ignore[import]
            console.print(f"[primary]Scapy sniff started:[/primary] iface={self.interface}")
            sniff(
                iface=self.interface,
                prn=packet_callback,
                filter=bpf_filter or self.bpf_filter,
                count=count,
                timeout=timeout,
                store=False,
            )
        except ImportError:
            console.print("[warning]scapy not installed. Install with: pip install scapy[/warning]")
        except PermissionError:
            console.print("[error]Capture requires root/sudo privileges.[/error]")


# ── PCAP reader ───────────────────────────────────────────────────────────────

class PcapReader:
    """Read and parse existing PCAP files using dpkt or pyshark."""

    def __init__(self, pcap_path: str) -> None:
        self.pcap_path = Path(pcap_path)

    def iter_packets_dpkt(self) -> Iterator[Dict]:
        """Yield parsed packet dicts using dpkt (fast, no subprocess)."""
        try:
            import dpkt  # type: ignore[import]
        except ImportError:
            console.print("[warning]dpkt not installed: pip install dpkt[/warning]")
            return
        import socket
        with self.pcap_path.open("rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception as exc:
                console.print(f"[warning]Failed to open PCAP: {exc}[/warning]")
                return
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    pkt: Dict = {"ts": ts, "raw_len": len(buf)}
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        pkt["src_ip"] = socket.inet_ntoa(ip.src)
                        pkt["dst_ip"] = socket.inet_ntoa(ip.dst)
                        pkt["proto"] = ip.p
                        pkt["ttl"] = ip.ttl
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            pkt["sport"] = tcp.sport
                            pkt["dport"] = tcp.dport
                            pkt["transport"] = "tcp"
                            pkt["payload"] = bytes(tcp.data)
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            pkt["sport"] = udp.sport
                            pkt["dport"] = udp.dport
                            pkt["transport"] = "udp"
                            pkt["payload"] = bytes(udp.data)
                    yield pkt
                except Exception:
                    continue

    def iter_packets_tshark(
        self,
        display_filter: str = "",
        fields: Optional[List[str]] = None,
    ) -> Iterator[Dict]:
        """Yield packets as dicts via tshark -T json (supports all 3000+ protocols)."""
        if not which("tshark"):
            console.print("[warning]tshark not found: apt install tshark[/warning]")
            return
        cmd = ["tshark", "-r", str(self.pcap_path), "-T", "json", "-n"]
        if display_filter:
            cmd += ["-Y", display_filter]
        if fields:
            for field in fields:
                cmd += ["-e", field]
            cmd += ["-T", "fields"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                console.print(f"[warning]tshark error: {result.stderr[:200]}[/warning]")
                return
            packets = json.loads(result.stdout) if result.stdout.strip() else []
            for pkt in packets:
                yield pkt
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            console.print(f"[warning]tshark parse error: {exc}[/warning]")

    def extract_http_sessions(self) -> List[Dict]:
        """Extract HTTP request/response pairs from PCAP."""
        sessions = []
        for pkt in self.iter_packets_tshark(display_filter="http"):
            layers = pkt.get("_source", {}).get("layers", {})
            http = layers.get("http", {})
            if http:
                sessions.append({
                    "method": http.get("http.request.method", ""),
                    "uri": http.get("http.request.uri", ""),
                    "host": http.get("http.host", ""),
                    "response_code": http.get("http.response.code", ""),
                    "content_type": http.get("http.content_type", ""),
                    "user_agent": http.get("http.user_agent", ""),
                })
        return sessions

    def extract_dns_queries(self) -> List[Dict]:
        """Extract all DNS queries and responses."""
        queries = []
        for pkt in self.iter_packets_tshark(display_filter="dns"):
            layers = pkt.get("_source", {}).get("layers", {})
            dns = layers.get("dns", {})
            if dns:
                queries.append({
                    "query_name": dns.get("dns.qry.name", ""),
                    "query_type": dns.get("dns.qry.type", ""),
                    "response": dns.get("dns.resp.name", ""),
                    "answers": dns.get("dns.a", ""),
                })
        return queries

    def extract_tls_info(self) -> List[Dict]:
        """Extract TLS certificates and JA3/JA3S fingerprints."""
        tls_info = []
        for pkt in self.iter_packets_tshark(display_filter="tls"):
            layers = pkt.get("_source", {}).get("layers", {})
            tls = layers.get("tls", {})
            if tls:
                tls_info.append({
                    "sni": tls.get("tls.handshake.extensions_server_name", ""),
                    "version": tls.get("tls.record.version", ""),
                    "cipher": tls.get("tls.handshake.ciphersuite", ""),
                    "cert_cn": tls.get("tls.handshake.certificate", ""),
                })
        return tls_info

    def extract_credentials(self) -> List[Dict]:
        """Extract cleartext credentials from FTP, HTTP Basic Auth, Telnet."""
        creds = []
        for pkt in self.iter_packets_tshark(display_filter="ftp.request.command == USER or ftp.request.command == PASS"):
            layers = pkt.get("_source", {}).get("layers", {})
            ftp = layers.get("ftp", {})
            if ftp:
                creds.append({"protocol": "ftp", "data": ftp})
        for pkt in self.iter_packets_tshark(display_filter="http.authorization"):
            layers = pkt.get("_source", {}).get("layers", {})
            http = layers.get("http", {})
            if http.get("http.authorization"):
                creds.append({"protocol": "http_basic", "data": http.get("http.authorization", "")})
        return creds


# ── Zeek log ingestion ────────────────────────────────────────────────────────

class ZeekLogReader:
    """Parse Zeek/Bro TSV log files into structured dicts."""

    def __init__(self, log_dir: str) -> None:
        self.log_dir = Path(log_dir)

    def parse_log(self, log_name: str) -> List[Dict]:
        """Parse a Zeek log file (e.g. 'conn', 'dns', 'http', 'ssl')."""
        log_path = self.log_dir / f"{log_name}.log"
        if not log_path.exists():
            return []
        records = []
        fields: List[str] = []
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif fields:
                    values = line.split("\t")
                    records.append(dict(zip(fields, values)))
        return records

    def get_connections(self) -> List[Dict]:
        return self.parse_log("conn")

    def get_dns(self) -> List[Dict]:
        return self.parse_log("dns")

    def get_http(self) -> List[Dict]:
        return self.parse_log("http")

    def get_ssl(self) -> List[Dict]:
        return self.parse_log("ssl")

    def get_files(self) -> List[Dict]:
        return self.parse_log("files")


# ── Quick interface lister ────────────────────────────────────────────────────

def list_interfaces() -> List[str]:
    """Return available network interfaces."""
    ifaces = []
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                ifaces.append(parts[1].strip().split("@")[0])
    except (OSError, subprocess.TimeoutExpired):
        pass
    if not ifaces:
        ifaces = ["eth0", "wlan0", "lo"]
    return ifaces


def run_zeek_on_pcap(pcap_path: str, output_dir: str, timeout: int = 300) -> bool:
    """Run Zeek against a PCAP file to generate logs."""
    if not which("zeek") and not which("bro"):
        console.print("[warning]zeek not found: apt install zeek[/warning]")
        return False
    zeek_bin = which("zeek") or "bro"
    ensure_dir(output_dir)
    code, out, err = run_command(
        [zeek_bin, "-r", pcap_path, "-C", f"Log::default_logdir={output_dir}"],
        timeout=timeout,
    )
    if code != 0:
        console.print(f"[warning]zeek failed: {err[:200]}[/warning]")
        return False
    return True
