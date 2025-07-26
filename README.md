# IP-Scourge

A high-performance, adaptive scanner for discovering Minecraft servers across the internet.

## Overview

IP-Scourge is a Python-based tool designed to scan IP ranges for active Minecraft servers, providing details such as server version, player count, MOTD, whitelist status, and online player names. It uses asynchronous I/O, connection pooling, and memory-mapped file storage for maximum performance while protecting your CPU.

## Features

- Scans optimized IP ranges from top hosting providers (Hetzner, OVH, DigitalOcean, AWS)
- Displays online player names for discovered servers
- Adaptive concurrency to prevent CPU overload
- Saves results to `found_servers.dat` with memory-mapped I/O
- High-speed scanning with precomputed packets and batch processing

## Requirements

- Python 3.11+
- Optional: `psutil` for better CPU monitoring (`pip install psutil`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/PanicAtTheKernl/IP-Scourge.git
   cd IP-Scourge
   ```

2. (Optional) Create a virtual environment:
   ```bash
   python3 -m venv mcscan-env
   source mcscan-env/bin/activate  # On Windows: mcscan-env\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install psutil
   ```

## Usage

Run the scanner:
```bash
python3 mc_scanner_maxpower.py
```

- Results are saved to `found_servers.dat` in the format: `IP:PORT | VERSION | PLAYERS | STATUS | MOTD | Players: PLAYER_NAMES`
- Press `Ctrl+C` to stop the scan and save partial results.

## Configuration

Edit the `main` function in `mc_scanner_maxpower.py` to adjust settings for your system:

```python
async def main():
    scanner = MinecraftServerScanner(
        max_concurrent=500,  # Reduce if CPU usage is too high
        timeout=1.5,         # Increase if network is slow
    )
    await scanner.scan_ranges(1500)  # Adjust max_ips_per_range for faster/slower scans
```

- `max_concurrent`: Number of simultaneous connections (lower for weaker CPUs).
- `timeout`: Seconds to wait for server responses (increase for slower networks).
- `max_ips_per_range`: IPs to scan per range (reduce for faster scans with less coverage).

## License

MIT License

## Contributing

Contributions are welcome! Please submit a pull request or open an issue on [GitHub](https://github.com/PanicAtTheKernl/IP-Scourge).

## Disclaimer

Use responsibly and respect server operators. Scanning large IP ranges may violate terms of service of some networks or hosting providers.
```
