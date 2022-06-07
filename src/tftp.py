# Due to class stuff, this is based on: git@github.com:jfgalamba/tftpy21180.git
import struct
import ipaddress
import re
import socket

from string import printable
from enum   import IntEnum, Enum
from typing import BinaryIO, Callable, List, Tuple, Union

## Constants and Types

INET4_Address  = Tuple[str, int]      # TCP/UDP address => IPv4 and port
File_Reference = Union[str, BinaryIO] # A path or a file object

MAX_DATA_LEN       = 512        # bytes
INACTIVITY_TIMEOUT = 30         # sec
MAX_BLOCK_NUM      = 2**16 - 1 
SOCKET_BUFFER_SIZE = 8192       # bytes
class TFTP_Mode(Enum):
    octect   = "octect"
    netascii = "netascii" # Nonfunctional as of yet

DEFAULT_MODE : TFTP_Mode = TFTP_Mode.octect

class TFTP_OpCode(IntEnum):
    RRQ = 1 # Read Request
    WRQ = 2 # Write Request
    DAT = 3 # Data
    ACK = 4 # Acknowledgement
    ERR = 5 # Error

def is_opcode(n : int) -> bool:
    """
    As I like to use enums I created this to check if the integer value is containted in TFTP_OpCode enum
    """
    try:
        TFTP_OpCode(n)
        return True
    except ValueError:
        return False

def int_to_OpCode(n: int) -> TFTP_OpCode:
    return TFTP_OpCode(n)

class TFTP_Error(IntEnum):
    UNDEF_ERROR              = 0
    FILE_NOT_FOUND           = 1
    ACCESS_VIOLATION         = 2
    DISK_FULL_ALLOC_EXCEEDED = 3
    ILLEGAL_OPERATION        = 4
    UNKNOWN_TRANSFER_ID      = 5
    FILE_EXISTS              = 6
    NO_SUCH_USER             = 7

_ERROR_MSGS : List[Tuple[TFTP_Error, str]] = [
    (TFTP_Error.UNDEF_ERROR              , "Undefined error."),
    (TFTP_Error.FILE_NOT_FOUND           , "File not found."),
    (TFTP_Error.ACCESS_VIOLATION         , "Access violation."),
    (TFTP_Error.DISK_FULL_ALLOC_EXCEEDED , "Disk full or allocation exceeded."),
    (TFTP_Error.ILLEGAL_OPERATION        , "Illegal TFTP operation."),
    (TFTP_Error.UNKNOWN_TRANSFER_ID      , "Unknown transfer ID."),
    (TFTP_Error.FILE_EXISTS              , "File already exists."),
    (TFTP_Error.NO_SUCH_USER             , "No such user"),
]
def TFTP_error_msg(err: TFTP_Error) -> str:
    """
    Turns TFTP_Error values into user readable strings
    """
    return _ERROR_MSGS[err][1]

#: End Constants and Types

### Packing and unpacking

def _pack_rq(opcode: TFTP_OpCode, filename: str, mode: TFTP_Mode = DEFAULT_MODE) -> bytes:
    if not is_ascii_printable(filename):
        raise ValueError(f'Invalid filename {filename} (not ascii printable)')
    if mode != TFTP_Mode.octect:
        raise ValueError(f'Invalid mode {mode}. Supported modes: octet.')
    pack_filename = byte_str(filename)
    pack_mode     = byte_str(str(mode))
    # "!H" -> unsigned int | size | "s"
    pack_format   = f"!H{len(pack_filename)}s{len(pack_mode)}s"
    return struct.pack(pack_format, opcode, pack_filename, pack_mode)

# TODO: Refresh my understanding of TFTP packet formation 
def _unpack_rq(packet: bytes) -> Tuple[str, str]:
    # I don't exactly understand the propper functioning of these next two lines
    filename_delim = packet.index(b'\x00', 2)
    filename = packet[2:filename_delim].decode()
    if not is_ascii_printable(filename):
        raise ValueError(f'Invalid filename {filename} (not ascii printable).')
    # Neither these two
    mode_delim = len(packet) - 1
    mode = packet[filename_delim + 1:mode_delim].decode()
    return (filename, mode)

def unpack_opcode(packet: bytes) -> TFTP_OpCode:
    # ? Why [:2]
    # "!H" -> unsigned short  
    opcode, *_ = struct.unpack("!H", packet[:2]) 
    if is_opcode(opcode):
        return int_to_OpCode(opcode)
    else:
        raise ValueError(f"Unrecognized opcode {opcode}")

def pack_dat(block_num : int, data:bytes) -> bytes:
    if not 0 <= block_num <= MAX_BLOCK_NUM:
        raise ValueError(f'Invalid block number {block_num}')
    if len(data) > MAX_DATA_LEN:
        raise ValueError(f'Invalid data length {len(data)} ')
    # uint uint | size - bytes 
    fmt = f'!HH{len(data)}s'
    return struct.pack(fmt, TFTP_OpCode.DAT, block_num, data)

def unpack_dat(packet: bytes) -> Tuple[int, bytes]:
    _, block_num = struct.unpack('!HH', packet[:4])
    return block_num, packet[4:]

def pack_rrq(filename: str, mode: TFTP_Mode = DEFAULT_MODE) -> bytes:
    return _pack_rq(TFTP_OpCode.RRQ, filename, mode)

def unpack_rrq(packet: bytes) -> Tuple[str, str]:
    return _unpack_rq(packet)

def pack_wrq(filename: str, mode: TFTP_Mode = DEFAULT_MODE) -> bytes:
    return _pack_rq(TFTP_OpCode.WRQ, filename, mode)

def unpack_wrq(packet: bytes) -> Tuple[str, str]:
    return _unpack_rq(packet)

def pack_ack(block_number: int) -> bytes:
    if not 0 >= block_number <= MAX_BLOCK_NUM:
        raise ValueError(f"Invalid block number {block_number}")
    return struct.pack('!HH', TFTP_OpCode.ACK, block_number)

def unpack_ack(packet: bytes) -> int:
    if len(packet) > 4:
        raise ValueError(f'Invalid packet length: {len(packet)}')
    return struct.unpack('!H', packet[2:4])[0] 

def unpack_err(packet: bytes) -> Tuple[int, str]:
    _, error_num, error_msg = struct.unpack(f'!HH{len(packet)-4}s', packet)
    return error_num, error_msg[:-1]

### 
##def pack_rrq(filename:str, mode:str = DEFAULT_MODE) -> bytes:
##    pack_filename = filename.encode() + b"\x00"
##    pack_mode     = mode.encode()     + b"\x00"
##    # see: https://docs.python.org/3/library/struct.html#format-characters
##    pack_format = f"!H{len(pack_filename)}s{len(pack_mode)}s"
##    return struct.pack(pack_format, TFTP_OpCode.RRQ, pack_filename, pack_mode)
##
##def unpack_rrq(packet: bytes) -> Tuple[str, str]:
##    filename_delim = packet.find(b"\x00", 2) 
##    mode_delim = len(packet) - 1
##    # This is returning (bytes, bytes) I am not sure if however I should
##    # actually convert to str or change the signature
##    return str(packet[2:filename_delim]), str(packet[filename_delim+1:mode_delim])
###

#: End: Pack and Unpacking

## Errors and Exceptions

class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """
#:

class ProtocolError(NetworkError):
    """
    A protocol error like unexpected or invalid opcode, wrong block 
    number, or any other invalid protocol parameter.
    """
#:

class Err(Exception):
    """
    An error sent by the server. It may be caused because a read/write 
    can't be processed. Read and write errors during file transmission 
    also cause this message to be sent, and transmission is then 
    terminated. The error number gives a numeric error code, followed 
    by an ASCII error message that might contain additional, operating 
    system specific information.
    """
    def __init__(self, error_code: int, error_msg: bytes):
        super().__init__(f'TFTP Error {error_code}')
        self.error_code = error_code
        self.error_msg = error_msg.decode()

#: End: Errors and Exceptions


## Commmon Utils

def byte_str(s :str) -> bytes:
    return s.encode() + b'\x00'

def is_ascii_printable(txt: str) -> bool:
    return not set(txt) - set(printable)

#* Note this is a "maker" function, it exists just to compile the RegEx and create the "is_valid_hostname()" function
def _make_is_valid_hostname() -> Callable[[str], bool]:
    # Warning: Dark RegEx Magic
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname: str) -> bool:
        """
        From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        See also: https://en.wikipedia.org/wiki/Hostname (and the RFC 
        referenced there)
        """
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname

is_valid_hostname = _make_is_valid_hostname()

# pylint: disable=raise-missing-from
pass

def get_server_info(server_addr: str) -> Tuple[str, str]:
    """
    Returns the server ip and hostname for server_addr. 
    This param may either be an IP address, in which case this function tries to query its hostname, or vice-versa.
    This functions raises a ValueError exception if the host name in server_addr is ill-formed, and raises NetworkError if we can't get
    an IP address for that host name.
    TODO: refactor code...
    """
    try:
        ipaddress.ip_address(server_addr)
    except ValueError:
        # server_addr not a valid ip address, then it might be a valid hostname
        if not is_valid_hostname(server_addr):
            raise ValueError(f"Invalid hostname: {server_addr}.")
        server_name = server_addr
        try:
            # gethostbyname_ex returns : 
            # (hostname, [aliaslist], [ipaddrlist])
            server_ip = socket.gethostbyname_ex(server_name)[2][0]
        except socket.gaierror:
            raise NetworkError(f"Unknown server: {server_name}.")
    else:  
        # server_addr is a valid ip address, get the hostname
        # if possible
        server_ip = server_addr
        try:
            # returns a tuple like gethostbyname_ex
            server_name = socket.gethostbyaddr(server_ip)[0]
        except socket.herror:
            server_name = ''
    return server_ip, server_name

#: End: Commmon Utils

def get_file(server_addr: INET4_Address , filename: str):
    """
    RRQ a file given by filename from a remote TFTP server given by server_addr.
    """
    # Open "filename" for writting and in binary mode (wb)
    with open(filename, "wb") as file:
        # Create DGRAM socket 
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(INACTIVITY_TIMEOUT)
            # Send RRQ through socket
            rrq = pack_rrq(filename)
            sock.sendto(rrq, server_addr)
            next_block_num = 1
            
            while True:
                # Wait for response 
                packet, new_serv_addr =  sock.recvfrom(SOCKET_BUFFER_SIZE)
                # Extract opcode
                opcode = unpack_opcode(packet)

                #(should be DAT)
                if opcode == TFTP_OpCode.DAT:
                    # Extract data and block num
                    block_num, data = unpack_dat(packet)
                    # if block_num is correct 
                    if block_num != next_block_num:
                        raise ProtocolError(f"Invalid Block Number {block_num}")
                    
                    # save data in file
                    file.write(data)
                    # send ack
                    sock.sendto(pack_ack((next_block_num)), new_serv_addr)
                    
                    # if the packet's data was smaller than max size then we know we're done
                    if len(data) < MAX_DATA_LEN:
                        break 
                # if Err 
                elif opcode == TFTP_OpCode.ERR:
                    # Raise and terminate RRQ
                    err_code, err_msg = unpack_err(packet)
                    raise Err(err_code, byte_str(err_msg))
                # else
                else:
                    # Raise protocol error
                    raise ProtocolError(f"Invalid opcode {opcode}")


def main() -> None :
    print()
    print("____ RRQ ____")
    rrq = pack_rrq('relatorio.pdf')
    print(rrq)
    filename, mode = unpack_rrq(rrq)
    print(f"Filename: {filename} Mode: {mode}")
    print()
    print("____ WRQ ____")
    wrq = pack_wrq('relatorio.pdf')
    print(wrq)
    filename, mode = unpack_wrq(wrq)
    print(f"Filename: {filename} Mode: {mode}")

if __name__ == "__main__":
    main()