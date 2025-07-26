# IP-Scourge: Minecraft Server Scanner

**IP-Scourge**, created by **PanicAtTheKernl**, is a Python-based tool for scanning Minecraft servers across IP ranges commonly used by hosting providers. Using asynchronous I/O, it efficiently detects servers, their status, player counts, MOTDs, whitelists, and online player names. Ideal for server admins or Minecraft enthusiasts exploring servers respectfully.

## Disclaimer

Use IP-Scourge responsibly. **PanicAtTheKernl** is not liable for misuse, such as griefing or disrupting servers. Scan and join only servers you’re permitted to, and always be respectful. Don’t ruin anyone’s fun!

## Features

- Asynchronous scanning with Python’s `asyncio` for high performance.
- Detects server version, player counts, MOTD, whitelist status, and online player names.
- Targets IP ranges from providers like Hetzner, OVH, DigitalOcean, AWS, Vultr, and Linode.
- Saves results to `found_servers.json` with scan statistics.
- Configurable concurrency, timeout, and port settings.
- Optional CPU monitoring with `psutil` for system performance insights.
- Progress monitoring with real-time scan statistics.

## Prerequisites

- **Python 3.8+**: Install via Linux package managers (`sudo apt install python3`, `sudo dnf install python3`, `sudo pacman -S python`) or from [python.org](https://www.python.org/downloads/). You’ve got this covered.
- **Git**: For cloning the repository.
- **Optional**: `psutil` for CPU monitoring (`pip install psutil`). If not installed, CPU monitoring is disabled.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/PanicAtTheKernl/IP-Scourge.git
   cd IP-Scourge
   ```

2. Install optional dependency (if desired):
   ```bash
   pip install psutil
   ```

3. No other dependencies required—runs on Python’s standard library.

## Usage

1. Run the scanner:
   ```bash
   python ip-scourge.py
   ```
   Scans IP ranges (1000 samples per range by default) and saves results to `found_servers.json`. Output includes server IP, port, version, player counts, MOTD, whitelist status, player names, and timestamp.

2. Customize settings in `ip-scourge.py` under the `main()` function:
   ```python
   scanner = MinecraftServerScanner(
       max_concurrent=100,  # Max concurrent scans (reduce if connection errors occur)
       timeout=3.0,        # Scan timeout in seconds (increase for slower networks)
       port=25565          # Minecraft server port
   )
   ```
   Adjust `samples_per_range` in `scan_ranges(samples_per_range=1000)` for more or fewer IPs per range.

3. View results in `found_servers.json`, which includes scan statistics and server details. Console output shows real-time progress and server info, including up to 5 player names per server.

## API Reference

### `MinecraftProtocol` Class
Handles Minecraft protocol operations.

- `pack_varint(value: int) -> bytes`: Encodes an integer as a varint.
- `unpack_varint(reader: asyncio.StreamReader, max_bytes: int = 5) -> int`: Decodes a varint from a stream.
- `pack_string(text: str) -> bytes`: Encodes a string with a varint length prefix (up to 32,767 bytes).
- `create_handshake_packet(host: str, port: int) -> bytes`: Creates a handshake and status request packet (protocol version 47, Minecraft 1.8.x).

### `MinecraftServerScanner` Class
Manages the scanning process.

- `__init__(max_concurrent: int = 100, timeout: float = 3.0, port: int = 25565)`: Initializes with concurrency, timeout, and port settings.
- `get_target_ip_ranges() -> List[str]`: Returns IP ranges from hosting providers (e.g., Hetzner, OVH, AWS).
- `generate_random_ips(ip_ranges: List[str], samples_per_range: int = 500) -> List[str]`: Generates random IPs from specified ranges.
- `ping_minecraft_server(ip: str) -> Optional[ServerResult]`: Pings a server, returning a `ServerResult` with version, player counts, MOTD, whitelist status, and player names.
- `scan_ip(ip: str) -> Optional[ServerResult]`: Scans an IP with concurrency control and logs results.
- `save_results()`: Saves results to `found_servers.json` every 50 successful scans.
- `progress_monitor(total_targets: int)`: Displays scan progress (percentage, rate, found servers).
- `scan_ranges(samples_per_range: int = 500)`: Runs the full scan, targeting specified IP ranges.

### `ServerResult` Dataclass
Stores server information:
- `ip: str`: Server IP address.
- `port: int`: Server port.
- `version: str`: Server version (e.g., "1.8.x").
- `players_online: int`: Current player count.
- `players_max: int`: Maximum player capacity.
- `motd: str`: Message of the Day (up to 200 characters).
- `whitelisted: bool`: Whether the server appears whitelisted (based on MOTD or player limits).
- `player_names: List[str]`: List of online player names.
- `timestamp: float`: Scan timestamp.

## Contributing

Want to improve IP-Scourge? Contributions are welcome:

1. Fork the repository: [github.com/PanicAtTheKernl/IP-Scourge](https://github.com/PanicAtTheKernl/IP-Scourge).
2. Create a branch:
   ```bash
   git checkout -b your-feature
   ```
3. Commit and push changes:
   ```bash
   git commit -m "Your changes"
   git push origin your-feature
   ```
4. Open a pull request.

Report issues or suggestions at [GitHub Issues](https://github.com/PanicAtTheKernl/IP-Scourge/issues).

## License

Licensed under the [MIT License](LICENSE).

## Contact

Questions or feedback? Open an issue on [GitHub](https://github.com/PanicAtTheKernl/IP-Scourge).
