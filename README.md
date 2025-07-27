```text
░██████░█████████       ░██████                                                                   
  ░██  ░██     ░██     ░██   ░██                                                                  
  ░██  ░██     ░██    ░██          ░███████   ░███████  ░██    ░██ ░██░████  ░████████  ░███████  
  ░██  ░█████████      ░████████  ░██    ░██ ░██    ░██ ░██    ░██ ░███     ░██    ░██ ░██    ░██ 
  ░██  ░██                    ░██ ░██        ░██    ░██ ░██    ░██ ░██      ░██    ░██ ░█████████ 
  ░██  ░██             ░██   ░██  ░██    ░██ ░██    ░██ ░██   ░███ ░██      ░██   ░███ ░██        
░██████░██              ░██████    ░███████   ░███████   ░█████░██ ░██       ░█████░██  ░███████  
                                                                                   ░██            
                                                                             ░███████             
```


Welcome to **IP-Scourge**, the Python script your firewall warned you about.

This unholy creation scans the internet for Minecraft servers like a deranged archaeologist with a pickaxe and no moral compass. It’s fast, it’s dirty, and it’s probably doing things Mojang would rather you didn’t. But hey—if they didn’t want us poking around, they shouldn’t have made the protocol so deliciously scrutable.

---

## 🚀 What It Does (aka Why You’re Here)

- 🧠 Uses `asyncio` to scan IPs faster than your caffeine-addled brain can comprehend
- 🕵️‍♂️ Digs up:
  - Server version
  - Player counts
  - MOTD (Message of the Day, or “please don’t DDoS us”)
  - Whitelist status
  - Online player names (yes, we see you, xXx_420Sniper_xXx)
- 🌍 Targets IP ranges from big-boy hosts like Hetzner, OVH, AWS, etc.
- 📦 Dumps results into `found_servers.json` like a good little data goblin
- 🛠️ Configurable concurrency, timeout, and port settings
- 🧮 Optional CPU monitoring via `psutil` (because your laptop is crying)
- 📊 Real-time progress updates so you can feel like a hacker in a bad movie

---

## 💬 NEW: Discord Integration

Because what’s better than scanning the internet for Minecraft servers?  
**Bragging about it in Discord.**

Use the companion script:  
**`ip-scourge-discord-integration.py`**

### 🔧 Setup

1. Open the file
2. Paste in your Discord bot token and channel IDs
3. Run it and bask in the glory of automated server spam
4. Watch your Discord channel fill with juicy server data

> 🧌 Perfect for flexing, monitoring, or summoning your fellow gremlins

---

## 📦 Installation

### Requirements

- Python 3.8+
- Git
- Optional: `psutil` for CPU stats

### Setup

```bash
git clone https://github.com/PanicAtTheKernl/IP-Scourge.git
cd IP-Scourge
pip install -r requirements.txt
```

---

## 🕹️ Usage

Run the main scanner:

```bash
python ip-scourge.py
```

Customize stuff in `ip-scourge.py`:

```python
scanner = MinecraftServerScanner(
    max_concurrent=100,  # Lower if your router starts sobbing
    timeout=3.0,         # Raise if you live in a potato-powered village
    port=25565           # Minecraft default, but you do you
)
```

Adjust `samples_per_range` in `scan_ranges()` to control how many IPs get violated per host.

Results go to `found_servers.json`, which you can open in your favorite JSON viewer or sacrifice to a data god.

---

## 🧪 API Reference (for Nerds)

### `MinecraftProtocol`
Handles Minecraft protocol magic:
- `pack_varint(value: int)`
- `unpack_varint(reader)`
- `pack_string(text)`
- `create_handshake_packet(host, port)`

### `MinecraftServerScanner`
Does the actual dirty work:
- `get_target_ip_ranges()`
- `generate_random_ips()`
- `ping_minecraft_server(ip)`
- `scan_ip(ip)`
- `save_results()`
- `progress_monitor()`
- `scan_ranges()`

### `ServerResult`
Stores server info like a digital trophy case:

```python
ServerResult(
    ip: str,
    port: int,
    version: str,
    players_online: int,
    players_max: int,
    motd: str,
    whitelisted: bool,
    player_names: List[str],
    timestamp: float
)
```

---

## 🤝 Contributing

Feel like making this worse? Better? More cursed?

1. Fork the repo  
2. Make your changes  
3. Open a pull request  
4. Wait for approval or divine intervention  
5. Or just scream into the GitHub Issues void

---

## 📜 License

MIT. Basically: do what you want, just don’t be a jerk.

---

## 🧩 About

Made by [PanicAtTheKernl](https://github.com/PanicAtTheKernl), IP-Scourge is a love letter to Minecraft, Python, and the thrill of poking things you probably shouldn’t.

---

> “If scanning IPs is wrong, I don’t want to be right.” – Probably you, after running this
