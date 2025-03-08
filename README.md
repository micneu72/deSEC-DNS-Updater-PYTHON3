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

## Requirements

- Python 3.6+
- Required packages: requests
- At least one DNS lookup tool (drill, host, dig, or nslookup)
