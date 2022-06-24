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
from typing import Dict, Any, Optional
from typing_extensions import Self
import docopt
from cmd import Cmd
# Cmd uses this optionall for more bash like behaviour
import readline # type: ignore

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
    return args.get('get') == False and args.get('put') == False
        
class UI(Cmd):
    def __is_connected(self: Self) -> bool:
        try:
            _ = self.srv
            return True
        except AttributeError:
            return False

    def do_get(self: Self, inp: str) -> None:
        if not tftp.is_ascii_printable(inp):
            print(f"{inp} is not a valid file")
            return None
        if not self.__is_connected():
            self.srv = tftp.INET4_Address.from_str(f"{self.prompt_server()}:69")
            return None
        tftp.get_file(self.srv, inp)

    def prompt_server(self) -> Optional[str]:
        inp = input("(server) ")
        if inp.strip() == "":
            self.do_help("connect")
            return None
        return inp
    def do_put(self: Self, inp: str) -> None:
        pass

    def do_dir(self: Self, inp: str) -> None:
        print("Not Implemented... Sorry :(")

    def do_connect(self: Self, inp: str) -> None:
        """
        Setup a connection to a TFTP server. 

        Usage: connect IP/HOSTNAME port | connect IP/HOSTNAME:PORT    
        """
        if inp == "":
            self.do_help("connect")
            return None
        try:
            srv_info = tftp.get_server_info(inp)
            self.prompt = f"tftp@{srv_info[0] if srv_info[1] == '' else srv_info[1]} >"
            self.srv = tftp.INET4_Address(srv_info[0], 69)
        except ValueError:
            self.do_help("connect")
        except tftp.NetworkError as e:
            print(e)

    def do_quit(self: Self, _):
        return True

    def do_help(self, arg: str) -> bool | None:
        return super().do_help(arg)

def cmd(server: tftp.INET4_Address, cmd: Command, file_name: str, outfile_name: Optional[str] ) -> None:
    if Command(cmd) == Command.get:
        tftp.get_file(server,file_name) #TODO: config output file name (needs extending get_file())
    elif Command(cmd) == Command.put:
        tftp.put_file(server, file_name)
    elif Command(cmd) == Command.dir:
        print(tftp.get_dir(server))

def main() -> None:
    args = docopt.docopt(str(__doc__), help=True)
    print(args)
    print(is_interactive(args))    
    if is_interactive(args):
        ui = UI()
        ui.prompt = "tftp > "
        ui.cmdloop()

if __name__ == "__main__":
    main()