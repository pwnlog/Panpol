# Panpol

Panpol is a cross-platform and multi-purpose payload generator.

> This project is still a demo, it may be used for CTFs for now.

# Menu

```
usage: panpol.py [-i <ip address>] [-p <port number>] [-a <payload type>] [-o <output file>] [-s] [-r] [-b] [-l] [-h]

  _____                        _
 |  __ \                      | |
 | |__) |_ _ _ __  _ __   ___ | |
 |  ___/ _` | '_ \| '_ \ / _ \| |
 | |  | (_| | | | | |_) | (_) | |
 |_|   \__,_|_| |_| .__/ \___/|_|
                  | |
                  |_|

            Version: 0.0.1
            Author: pwnlog

Main Options:
  -i <ip address>, --ip <ip address>
                        The IP address
  -p <port number>, --port <port number>
                        The port number
  -a <payload type>, --payload <payload type>
                        The payload type to generate
  -o <output file>, --output <output file>
                        The name of the output file

Module Options:
  -s, --smb             Generate smb payloads
  -r, --reverse         Generate reverse shell payloads
  -b, --bind            Generate bind shell payloads

Help Options:
  -l, --list            Lists the available payload types
  -h, --help            Show this help message and exit
```

# Manual Installation

Install panpol on Unix/Linux:

```
chmod +x panpol.py && sudo ln -sf $(pwd)/panpol.py /usr/local/bin/panpol.py 
```

# Automated Installation

Install panpol on Unix/Linux automatically:

```
chmod +x install.sh && sudo ./install.sh
```

# Usage

Generate SMB payloads:

```
python panpol.py -i <ip address> -p <port number> -a <smb payload type> -s
```

Generate reverse shells:

```
python panpol.py -i <ip address> -p <port number> -a <reverse shell payload type> -r
```

Generate bind shells:

```
python panpol.py -i <ip address> -p <port number> -a <reverse shell payload type> -b
```

# :heart: Development

I have created a [To Do](./TODO.md) list of things that I want to add.