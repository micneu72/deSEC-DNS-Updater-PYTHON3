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
