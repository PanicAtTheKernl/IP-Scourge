#!/usr/bin/env python3
"""
IP-Scourge: A high-performance Minecraft server scanner with player name detection.
GitHub: https://github.com/PanicAtTheKernl/IP-Scourge
License: MIT
"""

import asyncio
import socket
import struct
import time
import ipaddress
import random
from typing import Optional, Dict, List, Tuple
import json
import sys
import os
from dataclasses import dataclass, asdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None
    logger.warning("psutil not available - CPU monitoring disabled")

@dataclass
class ServerResult:
    ip: str
    port: int
    version: str
    players_online: int
    players_max: int
    motd: str
    whitelisted: bool
    player_names: List[str]
    timestamp: float

class MinecraftProtocol:
    """Handle Minecraft protocol operations"""

    @staticmethod
    def pack_varint(value: int) -> bytes:
        """Pack integer as varint"""
        if value < 0:
            raise ValueError("Varints cannot be negative")

        result = bytearray()
        while True:
            temp = value & 0x7F
            value >>= 7
            if value:
                result.append(temp | 0x80)
            else:
                result.append(temp)
                break
        return bytes(result)

    @staticmethod
    async def unpack_varint(reader: asyncio.StreamReader, max_bytes: int = 5) -> int:
        """Unpack varint from stream reader"""
        result = 0
        shift = 0
        bytes_read = 0

        while bytes_read < max_bytes:
            try:
                byte_data = await asyncio.wait_for(reader.read(1), timeout=2.0)
                if not byte_data:
                    return -1
                byte = byte_data[0]
            except (asyncio.TimeoutError, OSError):
                return -1

            bytes_read += 1
            result |= (byte & 0x7F) << shift

            if not (byte & 0x80):
                return result

            shift += 7
            if shift >= 32:
                return -1

        return -1

    @staticmethod
    def pack_string(text: str) -> bytes:
        """Pack string with length prefix"""
        encoded = text.encode('utf-8', errors='replace')[:32767]  # MC string limit
        return MinecraftProtocol.pack_varint(len(encoded)) + encoded

    @staticmethod
    def create_handshake_packet(host: str, port: int) -> bytes:
        """Create Minecraft handshake packet"""
        # Handshake packet
        handshake_data = (
            MinecraftProtocol.pack_varint(0) +  # Packet ID
            MinecraftProtocol.pack_varint(47) +  # Protocol version (1.8.x)
            MinecraftProtocol.pack_string(host) +
            struct.pack('>H', port) +
            MinecraftProtocol.pack_varint(1)  # Next state (status)
        )

        # Status request packet
        status_request = MinecraftProtocol.pack_varint(0)  # Packet ID

        # Combine packets with length prefixes
        handshake_packet = MinecraftProtocol.pack_varint(len(handshake_data)) + handshake_data
        status_packet = MinecraftProtocol.pack_varint(len(status_request)) + status_request

        return handshake_packet + status_packet

class MinecraftServerScanner:
    def __init__(self, max_concurrent: int = 250, timeout: float = 3.0, port: int = 25565):
        self.port = port
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.results: List[ServerResult] = []

        # Statistics
        self.stats = {
            'total_scanned': 0,
            'success_count': 0,
            'fail_count': 0,
            'start_time': 0,
        }

        # Concurrency control
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results_lock = asyncio.Lock()

        # Output settings
        self.output_file = "found_servers.json"
        self.save_interval = 50  # Save every N successful scans

    def get_target_ip_ranges(self) -> List[str]:
        """Get list of IP ranges commonly used by hosting providers"""
        return [
            # Hetzner
            "5.9.0.0/16", "78.46.0.0/15", "144.76.0.0/16", "148.251.0.0/16",
            "176.9.0.0/16", "213.239.192.0/18",

            # OVH
            "51.38.0.0/16", "145.239.0.0/16", "149.202.0.0/16", "151.80.0.0/16",

            # DigitalOcean
            "134.122.0.0/16", "137.184.0.0/16", "138.197.0.0/16", "157.245.0.0/16",
            "164.90.0.0/16", "167.71.0.0/16", "167.99.0.0/16", "178.62.0.0/16",

            # AWS (limited ranges)
            "3.208.0.0/12", "18.208.0.0/13", "54.208.0.0/12",

            # Vultr
            "45.32.0.0/12", "108.61.0.0/16", "149.28.0.0/16", "207.148.0.0/16",

            # Linode
            "172.104.0.0/15", "173.230.128.0/17", "45.79.0.0/16",
        ]

    async def generate_random_ips(self, ip_ranges: List[str], samples_per_range: int = 5000) -> List[str]:
        """Generate random IPs from specified ranges"""
        all_ips = []

        for ip_range in ip_ranges:
            try:
                network = ipaddress.IPv4Network(ip_range, strict=False)
                hosts = list(network.hosts())

                if hosts:
                    sample_size = min(len(hosts), samples_per_range)
                    sampled_ips = random.sample(hosts, sample_size)
                    all_ips.extend([str(ip) for ip in sampled_ips])

            except Exception as e:
                logger.warning(f"Failed to process IP range {ip_range}: {e}")
                continue

        random.shuffle(all_ips)
        logger.info(f"Generated {len(all_ips)} target IPs")
        return all_ips

    async def ping_minecraft_server(self, ip: str) -> Optional[ServerResult]:
        """Ping a single Minecraft server"""
        try:
            # Create connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.port),
                timeout=self.timeout
            )

            try:
                # Send handshake and status request
                packet = MinecraftProtocol.create_handshake_packet(ip, self.port)
                writer.write(packet)
                await asyncio.wait_for(writer.drain(), timeout=self.timeout)

                # Read response length
                response_length = await MinecraftProtocol.unpack_varint(reader)
                if response_length <= 0 or response_length > 32767:
                    return None

                # Read packet ID
                packet_id = await MinecraftProtocol.unpack_varint(reader)
                if packet_id != 0:
                    return None

                # Read JSON length
                json_length = await MinecraftProtocol.unpack_varint(reader)
                if json_length <= 0 or json_length > response_length:
                    return None

                # Read JSON data
                json_data = await asyncio.wait_for(
                    reader.read(json_length),
                    timeout=self.timeout
                )

                if len(json_data) != json_length:
                    return None

                # Parse JSON response
                try:
                    status = json.loads(json_data.decode('utf-8', errors='replace'))
                except json.JSONDecodeError:
                    return None

                # Extract server information
                version_info = status.get('version', {})
                players_info = status.get('players', {})

                # Get player sample
                player_sample = players_info.get('sample', [])
                player_names = [p.get('name', 'Unknown') for p in player_sample if isinstance(p, dict)]

                # Detect if server is whitelisted
                whitelisted = self._is_whitelisted(status)

                # Extract MOTD
                motd = self._extract_motd(status.get('description', ''))

                result = ServerResult(
                    ip=ip,
                    port=self.port,
                    version=version_info.get('name', 'Unknown')[:100],
                    players_online=players_info.get('online', 0),
                    players_max=players_info.get('max', 0),
                    motd=motd,
                    whitelisted=whitelisted,
                    player_names=player_names,
                    timestamp=time.time()
                )

                return result

            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass

        except Exception as e:
            logger.debug(f"Failed to ping {ip}: {e}")
            return None

    def _is_whitelisted(self, status: Dict) -> bool:
        """Detect if server appears to be whitelisted"""
        # Check description for whitelist keywords
        desc = self._extract_motd(status.get('description', '')).lower()
        whitelist_keywords = ['whitelist', 'private', 'restricted', 'members only', 'invite only']

        if any(keyword in desc for keyword in whitelist_keywords):
            return True

        # Check player counts (heuristic)
        players = status.get('players', {})
        online = players.get('online', 0)
        max_players = players.get('max', 0)

        # Small servers that are full might be whitelisted
        if max_players <= 20 and online == max_players and max_players > 0:
            return True

        return False

    def _extract_motd(self, description) -> str:
        """Extract MOTD from description object"""
        if isinstance(description, str):
            return description.replace('\n', ' ').strip()[:200]

        if isinstance(description, dict):
            text = description.get('text', '')

            # Handle extra components
            if 'extra' in description and isinstance(description['extra'], list):
                for extra in description['extra'][:10]:  # Limit to prevent huge MOTDs
                    if isinstance(extra, dict):
                        text += extra.get('text', '')
                    elif isinstance(extra, str):
                        text += extra

            return text.replace('\n', ' ').strip()[:200]

        return "Unknown MOTD"

    async def scan_ip(self, ip: str) -> Optional[ServerResult]:
        """Scan a single IP with concurrency control"""
        async with self.semaphore:
            self.stats['total_scanned'] += 1

            result = await self.ping_minecraft_server(ip)

            if result:
                async with self.results_lock:
                    self.results.append(result)
                    self.stats['success_count'] += 1

                    # Print result
                    player_list = ', '.join(result.player_names[:5]) if result.player_names else 'None'
                    if len(result.player_names) > 5:
                        player_list += f' (+{len(result.player_names) - 5} more)'

                    status_icon = '🔒' if result.whitelisted else '🔓'
                    print(f"✅ {result.ip}:{result.port} | {result.version} | "
                          f"{result.players_online}/{result.players_max} | {status_icon} | "
                          f"{result.motd[:50]} | Players: {player_list}")

                    # Save periodically
                    if len(self.results) % self.save_interval == 0:
                        await self.save_results()

                return result
            else:
                self.stats['fail_count'] += 1
                return None

    async def save_results(self):
        """Save results to JSON file"""
        if not self.results:
            return

        try:
            # Convert results to serializable format
            data = {
                'scan_info': {
                    'timestamp': time.time(),
                    'total_found': len(self.results),
                    'scan_duration': time.time() - self.stats['start_time'],
                    'stats': self.stats.copy()
                },
                'servers': [asdict(result) for result in self.results]
            }

            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved {len(self.results)} results to {self.output_file}")

        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    async def progress_monitor(self, total_targets: int):
        """Monitor and display scan progress"""
        while self.stats['total_scanned'] < total_targets:
            elapsed = time.time() - self.stats['start_time']
            rate = self.stats['total_scanned'] / elapsed if elapsed > 0 else 0

            progress = (self.stats['total_scanned'] / total_targets) * 100

            print(f"\r🚀 Progress: {progress:.1f}% | "
                  f"Scanned: {self.stats['total_scanned']:,}/{total_targets:,} | "
                  f"Found: {self.stats['success_count']:,} | "
                  f"Rate: {rate:.1f}/s | "
                  f"Elapsed: {elapsed:.0f}s", end='', flush=True)

            await asyncio.sleep(2)

    async def scan_ranges(self, samples_per_range: int = 500):
        """Main scanning function"""
        self.stats['start_time'] = time.time()

        # Generate target IPs
        logger.info("Generating target IP addresses...")
        ip_ranges = self.get_target_ip_ranges()
        targets = await self.generate_random_ips(ip_ranges, samples_per_range)

        if not targets:
            logger.error("No target IPs generated")
            return

        total_targets = len(targets)
        logger.info(f"Starting scan of {total_targets:,} IP addresses")
        logger.info(f"Concurrency: {self.max_concurrent}, Timeout: {self.timeout}s")

        # Start progress monitor
        progress_task = asyncio.create_task(self.progress_monitor(total_targets))

        try:
            # Create scanning tasks
            tasks = [self.scan_ip(ip) for ip in targets]

            # Run scans with progress updates
            await asyncio.gather(*tasks, return_exceptions=True)

        except KeyboardInterrupt:
            logger.info("\nScan interrupted by user")
        finally:
            progress_task.cancel()

            # Final save
            await self.save_results()

            # Print final statistics
            elapsed = time.time() - self.stats['start_time']
            print(f"\n\n=== Scan Complete ===")
            print(f"Total scanned: {self.stats['total_scanned']:,}")
            print(f"Servers found: {self.stats['success_count']:,}")
            print(f"Success rate: {(self.stats['success_count']/self.stats['total_scanned']*100):.2f}%")
            print(f"Scan duration: {elapsed:.1f}s")
            print(f"Average rate: {self.stats['total_scanned']/elapsed:.1f} scans/second")
            print(f"Results saved to: {self.output_file}")

async def main():
    """Main entry point"""
    # Configuration - adjust these based on your system
    scanner = MinecraftServerScanner(
        max_concurrent=1000,    # Reduce if you get connection errors
        timeout=1.0,          # Increase for slower networks
        port=25565            # Standard Minecraft port
    )

    try:
        await scanner.scan_ranges(samples_per_range=5000)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")

if __name__ == "__main__":
    # Set appropriate event loop policy for Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    asyncio.run(main())
