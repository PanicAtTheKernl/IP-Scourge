#!/usr/bin/env python3
"""
IP-Scourge (Enhanced): A high-performance, stealth-enhanced Minecraft server scanner with comprehensive logging.
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
import psutil
import threading
from dataclasses import dataclass, asdict
import logging
from logging.handlers import RotatingFileHandler
import aiohttp
from datetime import datetime
import traceback
import gc

# Enhanced logging setup with file rotation
def setup_logging():
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Main logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    # Console handler with colored output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '%(asctime)s | %(levelname)8s | %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        'logs/ipscourge.log', maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s | %(levelname)8s | %(funcName)s:%(lineno)d | %(message)s'
    )
    file_handler.setFormatter(file_format)
    
    # Error file handler
    error_handler = RotatingFileHandler(
        'logs/errors.log', maxBytes=5*1024*1024, backupCount=3
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_format)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    
    return logger

logger = setup_logging()

# Discord Bot Config (change these!)
DISCORD_BOT_TOKEN = "DISCORD BOT TOKEN HERE"
DISCORD_CHANNEL_ID = DISCORDD CHANNEL ID HERE
DISCORD_LOG_CHANNEL_ID = DISCORD LOGGING CHANNEL ID HERE

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
    response_time: float

@dataclass
class SystemStats:
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    network_sent_mb: float
    network_recv_mb: float
    active_connections: int
    scan_rate: float
    uptime_seconds: float

class MinecraftProtocol:
    @staticmethod
    def pack_varint(value: int) -> bytes:
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
        result = 0
        shift = 0
        for _ in range(max_bytes):
            try:
                byte_data = await asyncio.wait_for(reader.read(1), timeout=1.0)
                if not byte_data:
                    return -1
                byte = byte_data[0]
            except asyncio.TimeoutError:
                logger.debug("Varint read timeout")
                return -1
            except Exception as e:
                logger.debug(f"Varint read error: {e}")
                return -1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return result
            shift += 7
        logger.debug("Varint too long")
        return -1

    @staticmethod
    def pack_string(text: str) -> bytes:
        encoded = text.encode('utf-8', errors='replace')[:32767]
        return MinecraftProtocol.pack_varint(len(encoded)) + encoded

    @staticmethod
    def create_handshake_packet(host: str, port: int) -> bytes:
        handshake_data = (
            MinecraftProtocol.pack_varint(0) +
            MinecraftProtocol.pack_varint(47) +
            MinecraftProtocol.pack_string(host) +
            struct.pack('>H', port) +
            MinecraftProtocol.pack_varint(1)
        )
        status_request = MinecraftProtocol.pack_varint(0)
        return MinecraftProtocol.pack_varint(len(handshake_data)) + handshake_data + MinecraftProtocol.pack_varint(len(status_request)) + status_request

class DiscordLogger:
    def __init__(self, token: str, results_channel_id: int, log_channel_id: int):
        self.token = token
        self.results_channel_id = results_channel_id
        self.log_channel_id = log_channel_id
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=30
        )
        self.session = aiohttp.ClientSession(
            headers={"Authorization": f"Bot {self.token}"},
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=10)
        )
        self.message_queue = asyncio.Queue(maxsize=100)
        self.log_queue = asyncio.Queue(maxsize=50)
        self.rate_limiter = asyncio.Semaphore(5)  # Discord rate limiting
        
    async def start_workers(self):
        """Start background workers for message sending"""
        asyncio.create_task(self._message_worker())
        asyncio.create_task(self._log_worker())
        logger.info("Discord workers started")

    async def _message_worker(self):
        """Background worker for sending result messages"""
        while True:
            try:
                message = await self.message_queue.get()
                if message is None:  # Shutdown signal
                    break
                await self._send_to_channel(self.results_channel_id, message)
                await asyncio.sleep(0.5)  # Rate limiting
            except Exception as e:
                logger.error(f"Message worker error: {e}")

    async def _log_worker(self):
        """Background worker for sending log messages"""
        while True:
            try:
                message = await self.log_queue.get()
                if message is None:  # Shutdown signal
                    break
                await self._send_to_channel(self.log_channel_id, message)
                await asyncio.sleep(1.0)  # More conservative rate limiting for logs
            except Exception as e:
                logger.error(f"Log worker error: {e}")

    async def _send_to_channel(self, channel_id: int, content: str):
        """Send message to specific Discord channel"""
        async with self.rate_limiter:
            url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
            payload = {"content": content[:2000]}  # Discord message limit
            try:
                async with self.session.post(url, json=payload) as resp:
                    if resp.status == 429:  # Rate limited
                        retry_after = float(resp.headers.get('Retry-After', 1))
                        logger.warning(f"Discord rate limited, waiting {retry_after}s")
                        await asyncio.sleep(retry_after)
                    elif resp.status not in (200, 204):
                        logger.warning(f"Discord post failed: {resp.status} - {await resp.text()}")
                    else:
                        logger.debug(f"Message sent to channel {channel_id}")
            except Exception as e:
                logger.error(f"Discord send error: {e}")

    async def send_result(self, content: str):
        """Queue a result message"""
        try:
            await self.message_queue.put(content)
        except asyncio.QueueFull:
            logger.warning("Discord message queue full, dropping message")

    async def send_log(self, content: str):
        """Queue a log message"""
        try:
            await self.log_queue.put(content)
        except asyncio.QueueFull:
            logger.warning("Discord log queue full, dropping message")

    async def close(self):
        """Shutdown Discord logger"""
        logger.info("Shutting down Discord logger...")
        await self.message_queue.put(None)  # Shutdown signal
        await self.log_queue.put(None)  # Shutdown signal
        await asyncio.sleep(2)  # Give workers time to finish
        await self.session.close()

class SystemMonitor:
    def __init__(self, discord_logger: DiscordLogger):
        self.discord = discord_logger
        self.start_time = time.time()
        self.last_network_stats = psutil.net_io_counters()
        self.scan_count = 0
        self.last_scan_count = 0
        self.monitoring = True
        
    def get_system_stats(self) -> SystemStats:
        """Get current system statistics"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            
            # Network stats
            net_stats = psutil.net_io_counters()
            net_sent_mb = (net_stats.bytes_sent - self.last_network_stats.bytes_sent) / 1024 / 1024
            net_recv_mb = (net_stats.bytes_recv - self.last_network_stats.bytes_recv) / 1024 / 1024
            
            # Connection count (approximate)
            try:
                connections = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
            except (psutil.AccessDenied, OSError):
                connections = 0
            
            # Scan rate
            current_time = time.time()
            uptime = current_time - self.start_time
            scan_rate = (self.scan_count - self.last_scan_count) / max(1, uptime - (uptime - 30))
            self.last_scan_count = self.scan_count
            
            return SystemStats(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_gb=memory.used / 1024**3,
                memory_total_gb=memory.total / 1024**3,
                network_sent_mb=net_sent_mb,
                network_recv_mb=net_recv_mb,
                active_connections=connections,
                scan_rate=scan_rate,
                uptime_seconds=uptime
            )
        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return SystemStats(0, 0, 0, 0, 0, 0, 0, 0, 0)

    async def start_monitoring(self):
        """Start system monitoring loop"""
        logger.info("Starting system monitoring...")
        await self.discord.send_log("🖥️ **System Monitor Started**")
        
        while self.monitoring:
            try:
                stats = self.get_system_stats()
                
                # Log to console
                print(f"\r📊 CPU: {stats.cpu_percent:5.1f}% | RAM: {stats.memory_percent:5.1f}% "
                      f"| Scan Rate: {stats.scan_rate:6.1f}/s | Connections: {stats.active_connections:4d} "
                      f"| Uptime: {stats.uptime_seconds/3600:.1f}h", end="", flush=True)
                
                # Send to Discord every 30 seconds
                if int(stats.uptime_seconds) % 30 == 0:
                    embed_msg = (
                        f"📊 **System Status Report**\n"
                        f"```\n"
                        f"CPU Usage:     {stats.cpu_percent:5.1f}%\n"
                        f"Memory Usage:  {stats.memory_percent:5.1f}% ({stats.memory_used_gb:.1f}GB/{stats.memory_total_gb:.1f}GB)\n"
                        f"Scan Rate:     {stats.scan_rate:6.1f} scans/sec\n"
                        f"Connections:   {stats.active_connections:4d} active\n"
                        f"Network I/O:   ↑{stats.network_sent_mb:.1f}MB ↓{stats.network_recv_mb:.1f}MB\n"
                        f"Uptime:        {stats.uptime_seconds/3600:.1f} hours\n"
                        f"Total Scanned: {self.scan_count:,}\n"
                        f"```"
                    )
                    await self.discord.send_log(embed_msg)
                
                # Update network baseline
                self.last_network_stats = psutil.net_io_counters()
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(5)

    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        logger.info("System monitoring stopped")

    def increment_scan_count(self):
        """Increment the scan counter"""
        self.scan_count += 1

class MinecraftServerScanner:
    def __init__(self, max_concurrent: int = 250, timeout: float = 1.2, port: int = 25565):
        self.port = port
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.results: List[ServerResult] = []
        self.stats = {
            'total_scanned': 0, 
            'success_count': 0, 
            'fail_count': 0, 
            'timeout_count': 0,
            'error_count': 0,
            'start_time': 0
        }
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results_lock = asyncio.Lock()
        self.output_file = "found_servers.json"
        self.save_interval = 20
        self.discord = DiscordLogger(DISCORD_BOT_TOKEN, DISCORD_CHANNEL_ID, DISCORD_LOG_CHANNEL_ID)
        self.system_monitor = SystemMonitor(self.discord)
        
        # Connection pooling for better performance
        self.connection_pool = {}
        self.pool_lock = asyncio.Lock()

    def get_target_ip_ranges(self) -> List[str]:
        """Enhanced IP ranges with better targeting"""
        return [
            # Hetzner (Germany) - Popular for game servers
            "5.9.0.0/16", "78.46.0.0/15", "144.76.0.0/16", "159.69.0.0/16",
            "116.202.0.0/16", "95.216.0.0/16", "168.119.0.0/16",
            
            # OVH (France) - Large hosting provider
            "51.38.0.0/16", "145.239.0.0/16", "51.68.0.0/16", "51.77.0.0/16",
            "54.36.0.0/16", "91.121.0.0/16", "198.27.64.0/18",
            
            # DigitalOcean - Popular VPS provider
            "134.122.0.0/16", "138.197.0.0/16", "159.89.0.0/16", "165.22.0.0/16",
            "167.71.0.0/16", "167.99.0.0/16", "188.166.0.0/16", "206.189.0.0/16",
            
            # AWS EC2 ranges
            "3.208.0.0/12", "18.208.0.0/13", "52.0.0.0/11", "54.144.0.0/12",
            
            # Vultr
            "45.32.0.0/12", "108.61.0.0/16", "149.28.0.0/16", "207.148.0.0/16",
            
            # Linode
            "172.104.0.0/15", "45.79.0.0/16", "66.175.208.0/20", "96.126.96.0/19",
            
            # Scaleway
            "51.15.0.0/16", "163.172.0.0/16", "212.47.224.0/19",
            
            # Contabo
            "185.252.232.0/22", "207.180.192.0/18"
        ]

    async def generate_random_ips(self, ip_ranges: List[str], samples_per_range: int = 4000) -> List[str]:
        """Optimized IP generation with better distribution"""
        all_ips = []
        logger.info(f"Generating IPs from {len(ip_ranges)} ranges, {samples_per_range} samples each...")
        
        for i, ip_range in enumerate(ip_ranges):
            try:
                net = ipaddress.IPv4Network(ip_range, strict=False)
                hosts = list(net.hosts())
                
                if len(hosts) == 0:
                    logger.warning(f"No hosts in range {ip_range}")
                    continue
                    
                sample_size = min(samples_per_range, len(hosts))
                sample = random.sample(hosts, sample_size)
                all_ips.extend(map(str, sample))
                
                logger.debug(f"Range {i+1}/{len(ip_ranges)}: {ip_range} -> {sample_size} IPs")
                
            except Exception as e:
                logger.error(f"Failed to process IP range {ip_range}: {e}")
        
        random.shuffle(all_ips)
        logger.info(f"Generated {len(all_ips):,} target IPs")
        return all_ips

    async def ping_server(self, ip: str) -> Optional[ServerResult]:
        """Enhanced server ping with better error handling and timing"""
        start_time = time.time()
        reader = writer = None
        
        try:
            # Create connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.port), 
                timeout=self.timeout
            )
            
            # Send handshake packet
            packet = MinecraftProtocol.create_handshake_packet(ip, self.port)
            writer.write(packet)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)

            # Read response length
            length = await MinecraftProtocol.unpack_varint(reader)
            if length < 1 or length > 32767:
                logger.debug(f"Invalid packet length from {ip}: {length}")
                return None

            # Read packet ID
            packet_id = await MinecraftProtocol.unpack_varint(reader)
            if packet_id != 0:
                logger.debug(f"Invalid packet ID from {ip}: {packet_id}")
                return None

            # Read JSON length
            json_len = await MinecraftProtocol.unpack_varint(reader)
            if json_len < 1 or json_len > length:
                logger.debug(f"Invalid JSON length from {ip}: {json_len}")
                return None

            # Read JSON data
            data = await asyncio.wait_for(reader.read(json_len), timeout=self.timeout)
            if len(data) != json_len:
                logger.debug(f"Incomplete JSON data from {ip}: {len(data)}/{json_len}")
                return None

            # Parse server status
            status = json.loads(data.decode('utf-8', errors='replace'))
            response_time = time.time() - start_time
            
            # Extract player information
            player_sample = status.get('players', {}).get('sample', [])
            names = []
            if isinstance(player_sample, list):
                names = [p.get('name', 'Unknown') for p in player_sample[:10] if isinstance(p, dict)]
            
            # Extract MOTD
            motd = self._extract_motd(status.get('description', ''))
            
            # Extract version info
            version_info = status.get('version', {})
            version = version_info.get('name', 'Unknown') if isinstance(version_info, dict) else 'Unknown'
            
            # Extract player counts
            players_info = status.get('players', {})
            players_online = players_info.get('online', 0) if isinstance(players_info, dict) else 0
            players_max = players_info.get('max', 0) if isinstance(players_info, dict) else 0

            result = ServerResult(
                ip=ip,
                port=self.port,
                version=str(version)[:100],
                players_online=int(players_online) if isinstance(players_online, (int, float)) else 0,
                players_max=int(players_max) if isinstance(players_max, (int, float)) else 0,
                motd=motd,
                whitelisted=self._is_whitelisted(motd),
                player_names=names,
                timestamp=time.time(),
                response_time=response_time * 1000  # Convert to milliseconds
            )
            
            logger.debug(f"Successfully pinged {ip}: {version}, {players_online}/{players_max} players")
            return result

        except asyncio.TimeoutError:
            logger.debug(f"Timeout connecting to {ip}")
            self.stats['timeout_count'] += 1
            return None
        except json.JSONDecodeError as e:
            logger.debug(f"JSON decode error from {ip}: {e}")
            self.stats['error_count'] += 1
            return None
        except Exception as e:
            logger.debug(f"Error pinging {ip}: {type(e).__name__}: {e}")
            self.stats['error_count'] += 1
            return None
        finally:
            logger.info("🔄 Cleaning up...")
        
        # Final cleanup
        try:
            # Force close any remaining connections
            for task in asyncio.all_tasks():
                if not task.done():
                    task.cancel()
            
            # Wait a bit for tasks to cleanup
            await asyncio.sleep(1)
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

def print_banner():
    """Print startup banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                     IP-SCOURGE ENHANCED                      ║
║               High-Performance Minecraft Scanner             ║
║                    With System Monitoring                    ║
╠═══════════════════════════════════════════════════════════════╣
║  GitHub: https://github.com/PanicAtTheKernl/IP-Scourge      ║
║  License: MIT                                                ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    logger.info("IP-Scourge Enhanced initialized")

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_modules = ['psutil', 'aiohttp']
    missing = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        logger.error(f"Missing required modules: {', '.join(missing)}")
        logger.error("Please install with: pip install " + " ".join(missing))
        sys.exit(1)
    
    logger.info("✅ All dependencies satisfied")

def setup_directories():
    """Create necessary directories"""
    directories = ['logs', 'backups', 'results']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.debug(f"Directory ensured: {directory}/")

async def test_discord_connection(discord_logger):
    """Test Discord bot connection"""
    try:
        await discord_logger.send_log("🧪 **Connection Test** - IP-Scourge Enhanced is online!")
        logger.info("✅ Discord connection test successful")
        return True
    except Exception as e:
        logger.error(f"❌ Discord connection failed: {e}")
        logger.warning("Continuing without Discord logging...")
        return False

class ConfigManager:
    """Configuration management class"""
    def __init__(self):
        self.config_file = "config.json"
        self.default_config = {
            "scanning": {
                "max_concurrent": 250,
                "timeout": 1.2,
                "port": 25565,
                "samples_per_range": 5000,
                "save_interval": 20
            },
            "discord": {
                "enable_logging": True,
                "results_channel_id": DISCORD_CHANNEL_ID,
                "log_channel_id": DISCORD_LOG_CHANNEL_ID,
                "bot_token": DISCORD_BOT_TOKEN
            },
            "monitoring": {
                "system_stats_interval": 30,
                "progress_report_interval": 60,
                "enable_terminal_stats": True
            },
            "output": {
                "results_file": "found_servers.json",
                "backup_results": True,
                "log_level": "INFO"
            }
        }
    
    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"Configuration loaded from {self.config_file}")
                return config
            else:
                self.save_config(self.default_config)
                logger.info(f"Default configuration created at {self.config_file}")
                return self.default_config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self.default_config
    
    def save_config(self, config):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving config: {e}")

async def main():
    """Main execution function with enhanced startup"""
    try:
        # Print banner and setup
        print_banner()
        check_dependencies()
        setup_directories()
        
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        logger.info("🎮 IP-Scourge Enhanced - Starting up...")
        
        # System information
        cpu_count = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)
        disk_free_gb = psutil.disk_usage('.').free / (1024**3)
        
        logger.info(f"💻 System Information:")
        logger.info(f"   CPU Cores: {cpu_count}")
        logger.info(f"   Total RAM: {memory_gb:.1f}GB")
        logger.info(f"   Free Disk: {disk_free_gb:.1f}GB")
        
        # Auto-tune settings based on system specs and config
        scanning_config = config.get('scanning', {})
        
        if memory_gb >= 16 and cpu_count >= 8:
            max_concurrent = scanning_config.get('max_concurrent', 300)
            samples_per_range = scanning_config.get('samples_per_range', 6000)
            timeout = scanning_config.get('timeout', 1.0)
        elif memory_gb >= 8 and cpu_count >= 4:
            max_concurrent = scanning_config.get('max_concurrent', 200)
            samples_per_range = scanning_config.get('samples_per_range', 4000)
            timeout = scanning_config.get('timeout', 1.2)
        else:
            max_concurrent = scanning_config.get('max_concurrent', 150)
            samples_per_range = scanning_config.get('samples_per_range', 3000)
            timeout = scanning_config.get('timeout', 1.5)
        
        port = scanning_config.get('port', 25565)
        
        logger.info(f"⚙️  Scan Configuration:")
        logger.info(f"   Max Concurrent: {max_concurrent}")
        logger.info(f"   Timeout: {timeout}s")
        logger.info(f"   Target Port: {port}")
        logger.info(f"   Samples/Range: {samples_per_range:,}")
        
        # Initialize scanner
        scanner = MinecraftServerScanner(
            max_concurrent=max_concurrent, 
            timeout=timeout,
            port=port
        )
        
        # Update scanner config from file
        scanner.save_interval = scanning_config.get('save_interval', 20)
        scanner.output_file = config.get('output', {}).get('results_file', 'found_servers.json')
        
        # Test Discord connection if enabled
        discord_config = config.get('discord', {})
        if discord_config.get('enable_logging', True):
            logger.info("🔗 Testing Discord connection...")
            discord_ok = await test_discord_connection(scanner.discord)
            if not discord_ok:
                logger.warning("Discord logging disabled due to connection failure")
        
        # Pre-scan system check
        logger.info("🔍 Pre-scan system check...")
        initial_stats = scanner.system_monitor.get_system_stats()
        logger.info(f"   Initial CPU: {initial_stats.cpu_percent:.1f}%")
        logger.info(f"   Initial RAM: {initial_stats.memory_percent:.1f}%")
        
        if initial_stats.cpu_percent > 80:
            logger.warning("⚠️  High CPU usage detected, reducing concurrency...")
            max_concurrent = max(50, max_concurrent // 2)
            scanner.max_concurrent = max_concurrent
            scanner.semaphore = asyncio.Semaphore(max_concurrent)
        
        if initial_stats.memory_percent > 85:
            logger.warning("⚠️  High memory usage detected, reducing samples...")
            samples_per_range = max(1000, samples_per_range // 2)
        
        # Final startup message
        logger.info("🚀 All systems ready - Starting scan...")
        print(f"\n{'='*80}")
        print(f"🎯 SCAN STARTING - Target: {samples_per_range * len(scanner.get_target_ip_ranges()):,} IPs")
        print(f"⚡ Concurrency: {max_concurrent} | Timeout: {timeout}s | Port: {port}")
        print(f"📁 Results will be saved to: {scanner.output_file}")
        print(f"{'='*80}\n")
        
        # Run the enhanced scan
        await scanner.run_scan(samples_per_range=samples_per_range)
        
        # Post-scan summary
        print(f"\n{'='*80}")
        print("🏁 SCAN COMPLETED SUCCESSFULLY!")
        print(f"📊 Check your Discord channels and {scanner.output_file} for results")
        print(f"📋 Detailed logs saved in logs/ directory")
        print(f"{'='*80}")
        
    except KeyboardInterrupt:
        print("\n\n🛑 Scan interrupted by user (Ctrl+C)")
        logger.info("👋 Scan interrupted by user")
        print("📁 Partial results may be saved in found_servers.json")
        
    except Exception as e:
        logger.error(f"💥 Fatal error occurred: {e}")
        logger.error(f"📋 Full traceback:\n{traceback.format_exc()}")
        print(f"\n❌ Fatal error: {e}")
        print("📋 Check logs/errors.log for detailed error information")
        
    finally:
        logger.info("🔄 Performing final cleanup...")
        
        # Final cleanup and resource management
        try:
            # Cancel any remaining tasks
            pending_tasks = [task for task in asyncio.all_tasks() if not task.done()]
            if pending_tasks:
                logger.info(f"🧹 Cancelling {len(pending_tasks)} pending tasks...")
                for task in pending_tasks:
                    task.cancel()
                
                # Wait for tasks to cancel
                await asyncio.gather(*pending_tasks, return_exceptions=True)
            
            # Force garbage collection
            import gc
            gc.collect()
            
            logger.info("✅ Cleanup completed successfully")
            
        except Exception as cleanup_error:
            logger.error(f"❌ Error during cleanup: {cleanup_error}")
        
        print("\n👋 Thank you for using IP-Scourge Enhanced!")
        print("⭐ If you found this useful, consider starring the GitHub repo!")

if __name__ == '__main__':
    # Windows compatibility
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # Set up signal handlers for graceful shutdown
    import signal
    
    def signal_handler(sig, frame):
        print("\n🛑 Shutdown signal received...")
        logger.info(f"Received signal {sig}, initiating graceful shutdown...")
        # The KeyboardInterrupt will be handled by the main try/except
        raise KeyboardInterrupt
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the enhanced scanner
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass  # Already handled in main()
    except Exception as e:
        print(f"\n💥 Unhandled error: {e}")
        logging.shutdown()
        if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Error closing connection to {ip}: {e}")

    def _extract_motd(self, desc) -> str:
        """Enhanced MOTD extraction with better formatting"""
        try:
            if isinstance(desc, str):
                return desc.strip().replace('\n', ' ').replace('\r', '')[:200]
            elif isinstance(desc, dict):
                text = str(desc.get('text', ''))
                # Handle extra components
                extras = desc.get('extra', [])
                if isinstance(extras, list):
                    for extra in extras[:10]:  # Limit to prevent huge MOTDs
                        if isinstance(extra, dict):
                            text += str(extra.get('text', ''))
                        elif isinstance(extra, str):
                            text += extra
                return text.strip().replace('\n', ' ').replace('\r', '')[:200]
            else:
                return str(desc)[:200]
        except Exception as e:
            logger.debug(f"Error extracting MOTD: {e}")
            return "Unknown MOTD"

    def _is_whitelisted(self, motd: str) -> bool:
        """Enhanced whitelist detection"""
        if not isinstance(motd, str):
            return False
        motd_lower = motd.lower()
        wl_keywords = [
            'whitelist', 'private', 'restricted', 'invite only', 'members only',
            'application', 'apply', 'discord required', 'closed beta'
        ]
        return any(keyword in motd_lower for keyword in wl_keywords)

    async def scan_ip(self, ip: str):
        """Enhanced IP scanning with better stats tracking"""
        async with self.semaphore:
            self.stats['total_scanned'] += 1
            self.system_monitor.increment_scan_count()
            
            result = await self.ping_server(ip)
            
            if result:
                async with self.results_lock:
                    self.results.append(result)
                    self.stats['success_count'] += 1
                    
                    # Enhanced Discord message with more details
                    status_icon = "🔒" if result.whitelisted else "🔓"
                    player_info = f"{result.players_online}/{result.players_max}"
                    
                    msg = (f"✅ **{result.ip}:{result.port}** | {status_icon} | "
                          f"`{result.version}` | **{player_info}** players | "
                          f"`{result.response_time:.0f}ms` | {result.motd[:60]}")
                    
                    if result.player_names:
                        msg += f"\n👥 Players: {', '.join(result.player_names[:5])}"
                        if len(result.player_names) > 5:
                            msg += f" (+{len(result.player_names)-5} more)"
                    
                    logger.info(f"Found server: {result.ip}:{result.port} - {result.version} - {player_info} players")
                    await self.discord.send_result(msg)
                    
                    # Save results periodically
                    if len(self.results) % self.save_interval == 0:
                        await self.save_results()
            else:
                self.stats['fail_count'] += 1
            
            # Dynamic delay based on system load
            cpu_percent = psutil.cpu_percent(interval=None)
            if cpu_percent > 80:
                await asyncio.sleep(random.uniform(0.3, 0.8))
            elif cpu_percent > 60:
                await asyncio.sleep(random.uniform(0.1, 0.5))
            else:
                await asyncio.sleep(random.uniform(0.05, 0.3))

    async def save_results(self):
        """Enhanced result saving with backup"""
        try:
            # Create backup of existing file
            if os.path.exists(self.output_file):
                backup_file = f"{self.output_file}.backup"
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                os.rename(self.output_file, backup_file)
            
            # Save current results
            output_data = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'total_found': len(self.results),
                    'scan_stats': self.stats.copy()
                },
                'servers': [asdict(r) for r in self.results]
            }
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved {len(self.results)} servers to {self.output_file}")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
            logger.error(traceback.format_exc())

    def print_stats(self):
        """Print current scanning statistics"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['total_scanned'] / max(elapsed, 1)
        success_rate = (self.stats['success_count'] / max(self.stats['total_scanned'], 1)) * 100
        
        print(f"\n📈 **Scan Statistics:**")
        print(f"   Total Scanned: {self.stats['total_scanned']:,}")
        print(f"   Servers Found: {self.stats['success_count']:,}")
        print(f"   Success Rate:  {success_rate:.2f}%")
        print(f"   Scan Rate:     {rate:.1f} scans/sec")
        print(f"   Elapsed Time:  {elapsed/3600:.1f} hours")
        print(f"   Timeouts:      {self.stats['timeout_count']:,}")
        print(f"   Errors:        {self.stats['error_count']:,}")

    async def run_scan(self, samples_per_range: int = 5000):
        """Enhanced scan execution with monitoring"""
        logger.info("🚀 Starting enhanced IP-Scourge scan...")
        self.stats['start_time'] = time.time()
        
        # Start Discord workers and system monitoring
        await self.discord.start_workers()
        asyncio.create_task(self.system_monitor.start_monitoring())
        
        # Initial Discord notification
        await self.discord.send_log(
            f"🎯 **IP-Scourge Scan Started**\n"
            f"```\n"
            f"Target Port:     {self.port}\n"
            f"Concurrency:     {self.max_concurrent}\n"
            f"Timeout:         {self.timeout}s\n"
            f"Samples/Range:   {samples_per_range:,}\n"
            f"Expected Total:  ~{len(self.get_target_ip_ranges()) * samples_per_range:,} IPs\n"
            f"```"
        )
        
        try:
            # Generate target IPs
            targets = await self.generate_random_ips(self.get_target_ip_ranges(), samples_per_range)
            logger.info(f"🎯 Starting scan of {len(targets):,} IPs with {self.max_concurrent} concurrent connections")
            
            # Progress reporting
            async def progress_reporter():
                while self.stats['total_scanned'] < len(targets):
                    await asyncio.sleep(60)  # Report every minute
                    elapsed = time.time() - self.stats['start_time']
                    progress = (self.stats['total_scanned'] / len(targets)) * 100
                    rate = self.stats['total_scanned'] / max(elapsed, 1)
                    eta_seconds = (len(targets) - self.stats['total_scanned']) / max(rate, 1)
                    
                    self.print_stats()
                    
                    await self.discord.send_log(
                        f"📊 **Progress Report**\n"
                        f"```\n"
                        f"Progress:    {progress:5.1f}% ({self.stats['total_scanned']:,}/{len(targets):,})\n"
                        f"Found:       {self.stats['success_count']:,} servers\n"
                        f"Rate:        {rate:6.1f} scans/sec\n"
                        f"ETA:         {eta_seconds/3600:.1f} hours\n"
                        f"```"
                    )
            
            # Start progress reporting
            progress_task = asyncio.create_task(progress_reporter())
            
            # Run the scan
            await asyncio.gather(*(self.scan_ip(ip) for ip in targets))
            
            # Stop progress reporting
            progress_task.cancel()
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            logger.error(traceback.format_exc())
            await self.discord.send_log(f"❌ **Scan Error:** {str(e)}")
        
        finally:
            # Final save and cleanup
            await self.save_results()
            self.system_monitor.stop_monitoring()
            
            # Final statistics
            elapsed = time.time() - self.stats['start_time']
            self.print_stats()
            
            final_msg = (
                f"🏁 **Scan Complete!**\n"
                f"```\n"
                f"Total Time:      {elapsed/3600:.1f} hours\n"
                f"Servers Found:   {self.stats['success_count']:,}\n"
                f"Total Scanned:   {self.stats['total_scanned']:,}\n"
                f"Success Rate:    {(self.stats['success_count']/max(self.stats['total_scanned'],1)*100):.2f}%\n"
                f"Average Rate:    {self.stats['total_scanned']/max(elapsed,1):.1f} scans/sec\n"
                f"```\n"
                f"Results saved to: `{self.output_file}`"
            )
            
            logger.info("✅ Scan completed successfully!")
            await self.discord.send_log(final_msg)
            await self.discord.close()
            
            # Force garbage collection
            gc.collect()

async def main():
    """Main execution function"""
    try:
        logger.info("🎮 IP-Scourge Enhanced - Starting up...")
        
        # Optimized settings based on system capabilities
        cpu_count = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)
        
        # Auto-tune concurrency based on system specs
        if memory_gb >= 16 and cpu_count >= 8:
            max_concurrent = 300
            samples_per_range = 6000
        elif memory_gb >= 8 and cpu_count >= 4:
            max_concurrent = 200
            samples_per_range = 4000
        else:
            max_concurrent = 150
            samples_per_range = 3000
        
        logger.info(f"💻 System: {cpu_count} cores, {memory_gb:.1f}GB RAM")
        logger.info(f"⚙️  Auto-tuned: {max_concurrent} concurrent, {samples_per_range} samples/range")
        
        scanner = MinecraftServerScanner(
            max_concurrent=max_concurrent, 
            timeout=1.2,
            port=25565
        )
        
        await scanner.run_scan(samples_per_range=samples_per_range)
        
    except KeyboardInterrupt:
        logger.info("👋 Scan interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.error(traceback.format_exc())
    finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Error closing connection to {ip}: {e}")
