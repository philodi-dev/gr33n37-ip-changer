# gr33n37-ip-changer

Bash script that uses Tor to change your IP at specified intervals.

![gp](https://github.com/gr33n37/gr33n37-ip-changer/assets/30112537/34e1c4e2-ec79-4ef3-b0a2-e99eee48bb4b)

## Installation

You can either `git clone` the repository or `curl` the Bash script.

Using `git clone`:

```shell
git clone https://github.com/gr33n37/gr33n37-ip-changer.git
cd gr33n37-ip-changer
```

Using `curl`:

```shell
curl -O 'https://raw.githubusercontent.com/gr33n37/gr33n37-ip-changer/main/ip-changer.sh'
chmod +x ip-changer.sh
```

## Usage

### On Linux
Run the script with root privileges:

```shell
sudo ./ip-changer.sh
```

### On macOS
Run the script (no sudo required):

```shell
./ip-changer.sh
```

#### Requirements for macOS
- [Homebrew](https://brew.sh/) must be installed.
- The script will check for and install Tor and curl via Homebrew if needed.
- Tor is managed using `brew services`.

#### Requirements for Linux
- The script will attempt to install Tor and curl using your system's package manager (apt, yum, pacman, etc.).
- Tor is managed using `systemctl`.

First, enter how long you want to stay on one server before changing the IP.
Then, enter how many times to change the IP. Enter 0 for unlimited changes.

---

## Important Notes & Troubleshooting

### 1. Your Browser or Apps Must Use the Tor Proxy

This script changes your IP for traffic routed through the Tor SOCKS proxy (`127.0.0.1:9050`).
Most browsers and apps do **not** use this proxy by default. To hide your real IP, you must configure your browser or system to use the Tor proxy:

**Firefox:**
- Preferences → General → Network Settings → Settings...
- Select "Manual proxy configuration"
- Set SOCKS Host: `127.0.0.1` Port: `9050`
- Choose SOCKS v5
- Check "Proxy DNS when using SOCKS v5"

**Chrome/Chromium:**
- Start Chrome with:
  ```
  /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --proxy-server="socks5://127.0.0.1:9050"
  ```

**System-wide (macOS):**
- System Preferences → Network → Advanced → Proxies
- Set SOCKS Proxy to `127.0.0.1:9050`

### 2. Disable iCloud Private Relay and VPNs

If you see "Apple iCloud Private Relay" or a VPN in your IP info, your traffic is not using Tor.

- **Disable iCloud Private Relay:**
  - System Settings → [Your Name] → iCloud → Private Relay → Turn Off
- **Disable any other VPNs** while using this script.

### 3. IPv6 Leaks

Tor by default only handles IPv4. If your browser uses IPv6, your real IP may leak.
- Disable IPv6 in your network settings, or use browser add-ons to force IPv4.
- Or, configure your browser to use only IPv4 when using the Tor proxy.

### 4. Test Tor Proxy Directly

To verify Tor is working, run:
```bash
curl -s --socks5-hostname 127.0.0.1:9050 https://checkip.amazonaws.com
```
This should show a Tor exit node IP, not your real IP.

---

If you follow these steps, your public IP (as seen by websites) should match a Tor exit node, not your real IP or iCloud Private Relay IP.
