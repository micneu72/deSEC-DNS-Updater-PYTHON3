# deSEC-DNS-Updater-PYTHON3
# desec.py

A Python script to automatically update DNS entries at desec.io with Pushover notifications.

## Features

- Updates DNS records at desec.io when your IP address changes
- Supports both IPv4 and IPv6 address updates
- Sends optional Pushover notifications when IP changes occur
- Configurable via JSON configuration file
- Multiple IP detection methods for reliability
- Detailed logging and runtime statistics

## Usage

```bash
./desec.py [-c CONFIG_FILE] [-v]
```

### Options

- `-c, --config`: Path to configuration file (default: ./desec.json)
- `-v, --verbose`: Enable verbose output

## Configuration

The script uses a JSON configuration file with the following structure:

```json
{
    "token": "your_desec_token",
    "kodihost": "your.domain.example",
    "pushover": {
        "enabled": false,
        "user_key": "your_pushover_user_key",
        "app_token": "your_pushover_app_token"
    }
}
```

If the configuration file doesn't exist, a template will be created automatically.

## Setting up Automated Execution

### Linux (systemd Timer)

For automated execution on Linux systems using systemd, you can set up a timer instead of using cron:

1. Create a service file at `/etc/systemd/system/desec-updater.service`:

```
[Unit]
Description=deSEC DNS Updater Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/path/to/your/desec
# Optional: If you want to run as a specific user
# User=yourusername
# Group=yourusername

[Install]
WantedBy=multi-user.target
```

2. Create a timer file at `/etc/systemd/system/desec-updater.timer`:

```
[Unit]
Description=Run deSEC DNS Updater periodically

[Timer]
# Run 5 minutes after boot
OnBootSec=5min
# Repeat every 15 minutes
OnUnitActiveSec=15min
# Alternative: use a fixed schedule
# OnCalendar=*:0/15

[Install]
WantedBy=timers.target
```

3. Enable and start the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable desec-updater.timer
sudo systemctl start desec-updater.timer
```

4. Check the timer status:

```bash
systemctl status desec-updater.timer
systemctl list-timers --all
```

### macOS (launchd)

For automated execution on macOS, you can use launchd:

1. Create a plist file at `~/Library/LaunchAgents/com.user.desec-updater.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.desec-updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/your/desec</string>
    </array>
    <key>StartInterval</key>
    <integer>900</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/desec-updater.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/desec-updater.out</string>
</dict>
</plist>
```

2. Load and start the job:

```bash
launchctl load ~/Library/LaunchAgents/com.user.desec-updater.plist
```

3. To check if it's running:

```bash
launchctl list | grep desec
```

## Compatibility Notes

- The Linux binaries were tested on Ubuntu 24.04 and Kali Linux Rolling
- Linux binaries may require GLIBC 2.38 or newer
- If you're using an older Linux distribution (like Debian Bullseye), you may need to compile the binary yourself or use the Python script directly
- macOS binaries were tested on macOS 15.3.1 (Sequoia) (Apple Silicon/ARM)
- For best compatibility across different Linux distributions, consider using the Python script instead of the pre-compiled binaries

## macOS Security Notice

When running the binary on macOS for the first time, you may encounter a security warning as the application is from an "unidentified developer." To run the application:

1. Locate the binary in Finder
2. Right-click (or Control-click) on the binary
3. Select "Open" from the context menu
4. Click "Open" in the dialog that appears

Alternatively, you can allow the application in System Settings:
1. Go to System Settings > Privacy & Security
2. Scroll down to the "Security" section
3. Look for the message about the blocked application and click "Allow Anyway"
4. Enter your administrator password if prompted

After completing these steps, you'll be able to run the application normally.

## Requirements

- Python 3.6+
- Required packages: requests
- At least one DNS lookup tool (drill, host, dig, or nslookup)

Quellen
