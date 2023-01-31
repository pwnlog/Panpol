#!/usr/bin/env python3

# Author: pwnlog
# Description: A cross-platform and multi-purpose payload generator
# Notes: This is a demo version. The code needs to be improved.

from argparse import RawTextHelpFormatter
import argparse
import sys
import ipaddress
from payloads import smb, bind_shells, reverse_shells
import os.path
#import inspect

def verify_ip(ip):
    try:
        ip = ipaddress.ip_address(ip)
        print('[+] The IPv{1} address is valid: {0}'.format(ip, ip.version))
    except ValueError:
        print('[-] The address is invalid: {0}'.format(ip))
        exit(1)

def verify_port(port):
    try:
        if 1 <= port <= 65535:
            print('[+] The port number is valid: {0}'.format(port))
        else:
            raise ValueError
    except ValueError:
        print('[-] The port number is invalid: {0}'.format(port))
        exit(1)

def verify_payload(payload, module):
    smb_payloads = ["scf", "url", "ini", "lib"]
    rev_payloads = ["python", "powershell"]
    bind_payloads = ["python", "powershell"]

    if module == "smb":
        if payload not in smb_payloads:
            print(f"[-] Invalid payload specified: {payload}")
            exit(1)

    if module == "reverse":
        if payload not in rev_payloads:
            print(f"[-] Invalid payload specified: {payload}")
            exit(1)

    if module == "bind":
        if payload not in bind_payloads:
            print(f"[-] Invalid payload specified: {payload}")
            exit(1)

def strip_output(output):
    return os.path.basename(output)

def write_file(fname, payload):
    with open(fname, 'w+') as f:
        f.write(payload)
        print(f"[+] Created a file named: {fname}")

def list_payloads():
    print("""
SMB Payloads:
scf
url
ini
lib

Reverse Shell Payloads:
python
powershell

Bind Shell Payloads:
python
powershell
    """)

def reverse_payloads(ip, port, payload, output):
    if output is not None:
        filename = strip_output(output)
    else:
        print("[i] Printing the payload only")
        print("[i] An output file won't be created")

    if payload == "python":
        rev_payload = reverse_shells.reverse_python_tcp.format(ip, port)
        print(f"[+] Generating {payload} reverse shell payload\n")
        print(f"{rev_payload}\n")
        if output is not None:
            fname = f'{filename}.txt'
            write_file(fname, rev_payload)

    if payload == "powershell":
        rev_payload = reverse_shells.reverse_powershell_tcp.replace("IP", ip).replace("PORT", str(port))
        print(f"[+] Generating {payload} reverse shell payload\n")
        print(f"{rev_payload}\n")
        if output is not None:
            fname = f'{filename}.txt'
            write_file(fname, rev_payload)
    
    if payload is None and output is None:
        print("[+] Generating reverse shell payloads\n")
        rev_payload = reverse_shells.reverse_python_tcp.format(ip, port)
        print(f"{rev_payload}\n")
        rev_payload = reverse_shells.reverse_powershell_tcp.replace("IP", ip).replace("PORT", str(port))
        print(f"{rev_payload}\n")

    if payload is None and output is not None:
        print("[+] Generating reverse shell payloads\n")
        rev_payload = reverse_shells.reverse_python_tcp.format(ip, port)
        print(f"{rev_payload}\n")
        fname = f'{filename}1.txt'
        write_file(fname, rev_payload)
        rev_payload = reverse_shells.reverse_powershell_tcp.replace("IP", ip).replace("PORT", str(port))
        print(f"{rev_payload}\n")
        fname = f'{filename}2.txt'
        write_file(fname, rev_payload)

def bind_payloads(port, payload, output):
    if output is not None:
        filename = strip_output(output)
    else:
        print("[i] Printing the payload only")
        print("[i] An output file won't be created")

    if payload == "python":
        bind_payload = bind_shells.bind_python_tcp.replace("PORT", str(port))
        print(f"[+] Generating {payload} bind shell payload\n")
        print(f"{bind_payload}\n")
        if output is not None:
            fname = f'{filename}.txt'
            write_file(fname, bind_payload)

    if payload == "powershell":
        bind_payload = bind_shells.bind_powershell_tcp.replace("PORT", str(port))
        print(f"[+] Generating {payload} bind shell payload\n")
        print(f"{bind_payload}\n")
        if output is not None:
            fname = f'{filename}.txt'
            write_file(fname, bind_payload)

    if payload is None and output is None:
        print("[+] Generating bind shell payloads\n")
        bind_payload = bind_shells.bind_python_tcp.replace("PORT", str(port))
        print(f"{bind_payload}\n")
        bind_payload = bind_shells.bind_powershell_tcp.replace("PORT", str(port))
        print(f"{bind_payload}\n")

    if payload is None and output is not None:
        print("[+] Generating bind shell payloads\n")
        
        bind_payload = bind_shells.bind_python_tcp.replace("PORT", str(port))
        print(f"{bind_payload}\n")
        fname = f'{filename}1.txt'
        write_file(fname, bind_payload)
        
        bind_payload = bind_shells.bind_powershell_tcp.replace("PORT", str(port))
        print(f"{bind_payload}\n")
        fname = f'{filename}2.txt'
        write_file(fname, bind_payload)
  

def smb_payloads(ip, port, payload, output):
    if output is not None:
        filename = strip_output(output)
    else:
        print("[i] Printing the payload only")
        print("[i] An output file won't be created")
    
    if payload == "scf":
        scf_payload = smb.scf.format(ip, port)
        print(f"[+] Generating SMB {payload} payload\n")
        print(f"{scf_payload}\n")
        if output is not None:
            fname = f'@{filename}.scf'
            write_file(fname, scf_payload)
    
    elif payload == "url":
        url_payload = smb.url.format(ip, port, ip, port)
        print(f"[+] Generating SMB {payload} payload\n")
        print(f"{url_payload}\n")
        if output is not None:
            fname = f'@{filename}.url'
            write_file(fname, url_payload)
    
    elif payload == "lib":
        lib_payload = smb.lib.format(ip, port, port)
        lib_payload = lib_payload.replace("[","{").replace("]","}")
        print(f"[+] Generating SMB {payload} payload\n")
        print(f"{lib_payload}\n")
        if output is not None:
            fname = f'{filename}.library-ms'
            write_file(fname, lib_payload)
    
    elif payload == "ini":
        ini_payload = smb.ini.format(ip, port, port)
        print(f"[+] Generating SMB {payload} payload\n")
        print(f"{ini_payload}\n")
        if output is not None:
            fname = f'desktop.ini'
            write_file(fname, ini_payload)
    
    if payload is None and output is None:
        print("[+] Generating SMB payloads\n")
        
        scf_payload = smb.scf.format(ip, port)
        print(f"{scf_payload}\n")
        url_payload = smb.url.format(ip, port, ip, port)
        print(f"{url_payload}\n")
        lib_payload = smb.lib.format(ip, port, port)
        lib_payload = lib_payload.replace("[","{").replace("]","}")
        print(f"{lib_payload}\n")
        ini_payload = smb.ini.format(ip, port, port)
        print(f"{ini_payload}\n")

    if payload is None and output is not None:
        print("[+] Generating SMB payloads\n")
        
        scf_payload = smb.scf.format(ip, port)
        print(f"{scf_payload}\n")
        fname = f'@{filename}.scf'
        write_file(fname, scf_payload)

        url_payload = smb.url.format(ip, port, ip, port)
        print(f"{url_payload}\n")
        fname = f'@{filename}.url'
        write_file(fname, url_payload)
        
        lib_payload = smb.lib.format(ip, port, port)
        lib_payload = lib_payload.replace("[","{").replace("]","}")
        print(f"{lib_payload}\n")
        fname = f'{filename}.library-ms'
        write_file(fname, lib_payload)

        ini_payload = smb.ini.format(ip, port, port)
        print(f"{ini_payload}\n")
        fname = f'desktop.ini'
        write_file(fname, ini_payload)


def main():
    parser = argparse.ArgumentParser(description=f"""
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
""", 
    formatter_class=RawTextHelpFormatter, add_help=False, allow_abbrev=False)
    
    # Main Options
    parser._optionals.title = "Main Options"
    parser.add_argument(
        "-i",
        "--ip",
        metavar="<ip address>",
        action="store",
        type=str,
        help="The IP address"
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<port number>",
        action="store",
        type=int,
        help="The port number"
    )
    parser.add_argument(
        "-a",
        "--payload",
        metavar="<payload type>",
        action="store",
        type=str,
        help="The payload type to generate"
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="<output file>",
        type=str,
        help="The name of the output file"
    )

    # Modules Options
    module_arg = parser.add_argument_group("Module Options")
    module_arg.add_argument(
        "-s",
        "--smb",
        action="store_true",
        help="Generate smb payloads"
    )
    module_arg.add_argument(
        "-r",
        "--reverse",
        action="store_true",
        help="Generate reverse shell payloads"
    )
    module_arg.add_argument(
        "-b",
        "--bind",
        dest="bind", 
        action="store_true",
        help="Generate bind shell payloads"
    )

    # Help Options
    help_arg = parser.add_argument_group("Help Options")
    help_arg.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="Lists the available payload types"
    )
    help_arg.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit"
    )

    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    args = parser.parse_args()

    if args.list is True:
        list_payloads()

    if args.smb is True:
        module = "smb" 
        if args.ip is not None and args.port is not None:
            verify_ip(args.ip)
            verify_port(args.port)
        else:
            print("[-] Error: Please specify an IP address and a port number")
            exit(1)
        if args.payload is not None:
            verify_payload(args.payload, module)
            smb_payloads(args.ip, args.port, args.payload, args.output)
        else:
            smb_payloads(args.ip, args.port, args.payload, args.output)


    if args.bind is True:
        module = "bind" 
        if args.port is not None:
            verify_port(args.port)
        else:
            print("[-] Error: Please specify a port number")
            exit(1)
        if args.payload is not None:
            verify_payload(args.payload, module)
            bind_payloads(args.port, args.payload, args.output)
        else:
            bind_payloads(args.port, args.payload, args.output)

    if args.reverse is True:
        module = "reverse"
        if args.ip is not None and args.port is not None:
            verify_ip(args.ip)
            verify_port(args.port)
        else:
            print("[-] Error: Please specify an IP address and a port number")
            exit(1)
        if args.payload is not None:
            verify_payload(args.payload, module)
            reverse_payloads(args.ip, args.port, args.payload, args.output)
        else:
            reverse_payloads(args.ip, args.port, args.payload, args.output)

if __name__ == "__main__":
    main()