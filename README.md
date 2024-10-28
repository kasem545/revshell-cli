
# Reverse Shell Generator

A Python script to generate reverse shell commands in various formats and display a Netcat command for listening. This tool is intended for ethical hacking purposes only.

## Features

- Supports multiple reverse shell formats across different scripting languages and protocols.
- Generates Netcat command for listening on the specified port.
- Provides an option to display available reverse shell formats.

## Installation

### Requirements

- Python 3.x
- Install required Python library with:
    ```bash
    pip install -r requirements.txt
    ```

### Dependencies

- `argparse`: Standard library, no installation required.
- `colorama`: For colored terminal output. Install with:
    ```bash
    pip install colorama
    ```

## Usage

Run the script using the following options:

```bash
python3 revshell.py [-i IP_ADDRESS] [-p PORT] [-t SHELL_TYPE] [-fh]
```

### Arguments:

- `-i`, `--ip_host`: IP address for the reverse shell connection.
- `-p`, `--port`: Port to listen on for the reverse shell.
- `-t`, `--type`: Type of reverse shell (e.g., `bash -i`, `nc -e`, `python`, etc.).
- `-fh`, `--format-help`: Display all available reverse shell formats (types) without the full command.

### Example

Generate a reverse shell command for `bash -i`:

```bash
python3 revshell.py -i 192.168.1.1 -p 4444 -t "bash -i"
```

Display available formats:

```bash
python3 revshell.py -fh
```

## License

This project is licensed under the MIT License.

## Disclaimer

This script is designed for educational and ethical hacking purposes only. Unauthorized use of this tool on a network or system without permission is illegal.
