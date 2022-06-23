#!/usr/bin/python3
"""TFTPy - This module implements an interactive and command line TFTP client.

Usage:
    client.py (get | put) [-p <serv_port>] <server> <source_file> [<dest_file>] 
    client.py [-p <serv_port>] <server>
    client.py (-h | --help)

Options:
    -h, --help      Display help
    <server>        TFTP server name or IP address [type: str]
    -p <serv_port>  TFTP server port [default: 69] [type: int]

Usage by:(C) João Galamba, 2022
Code by: João Correia, Maria Graça Lopes; 2022
"""

from dataclasses import dataclass
from enum import Enum
from operator import truediv
from socket import socket
from typing import Dict, Any, Optional
import docopt

import tftp

@dataclass
class Input():
    server : tftp.INET4_Address
    port : int
    get : bool
    put : bool
    src_file_name: str
    dst_file_name: str
    help : bool

def help() -> None:
    print(__doc__)
class Command(Enum):
    get = "get"
    put = "put"
    dir = "dir"

def is_interactive(args: Dict[str, Any]) -> bool:
    try:
        return bool(args.get("get")) or bool(args.get("put"))
    except ValueError:
        assert False, "Who touched the docstring ?"

def cmd(server: tftp.INET4_Address, cmd: Command, file_name: str, outfile_name: Optional[str] ) -> None:
    if Command(cmd) == Command.get:
        tftp.get_file(server,file_name) #TODO: config output file name (needs extending get_file())
    elif Command(cmd) == Command.put:
        tftp.put_file(server, file_name)
    elif Command(cmd) == Command.dir:
        print(tftp.get_dir(server))
    
def user_prompt(state: Any) -> None:
    print("tftp > ")

def get_input() -> str:
    pass

def process_input(server: tftp.INET4_Address, imp: str) -> str:
    pass

def get_server_input() -> str:
    pass

def execute_cmd() -> None:
    pass

def interactive(args: Dict[str, Any]) -> None:
    if args.get("<server>") is None:
        server : tftp.INET4_Address = (tftp.get_server_info(get_server_input())[0], (69 if args.get("<port>") is None else args.get("<port>")))  
    else:
        server = (tftp.get_server_info(args.get("<server>"))[0], (69 if args.get("<port>") is None else args.get("<port>")))  

    while True:
        user_prompt(None)
        process_input(server,get_input())
        execute_cmd()

def main() -> None:
    args = docopt.docopt(str(__doc__), help=True)
    print(args)
    print(is_interactive(args))    

if __name__ == "__main__":
    main()