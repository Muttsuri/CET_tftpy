# Due to class stuff, this is based on: git@github.com:jfgalamba/tftpy21180.git
import math
import os
import struct
import ipaddress
import re
import socket

from string            import printable
from enum              import IntEnum, Enum
from typing            import Any, BinaryIO, Callable, Dict, Tuple, Union
from typing_extensions import Self

File_Reference = Union[str, BinaryIO] # A path or a file object

## Constants and Types
MAX_DATA_LEN       = 512        # bytes
INACTIVITY_TIMEOUT = 30         # sec
MAX_BLOCK_NUM      = 2**16 - 1 
SOCKET_BUFFER_SIZE = 8192       # bytes

class INET4_Address:
    def __init__(self, ip: str, port: int) -> None:
        if not self.is_valid_ip(ip):
            raise ValueError(f"{ip} is not a valid ip address")
        self.__addr = ip
        self.__port = port

    @property
    def addr(self: Self) -> str:
        return self.__addr

    @property
    def port(self: Self) -> int:
        return self.__port

    @property
    def value(self:Self) -> Tuple[str, int]:
        return (self.__addr, self.__port)

    # Evil Regex
    @staticmethod
    def is_valid_ip(str: str) -> bool:
        # Recompiling is not much of an issue since re.compile() implements caching
        #   thus if the regex doesn't change (which it doesn't in this case) the 
        #   recompilation cost is just the cost of a dictionary lookup.
        return bool(
                re
                .compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
                .match(str))

    @classmethod
    def from_tuple(cls, tpl: Tuple[str, int]) -> Self:
        return cls(tpl[0], tpl[1])

    @classmethod
    def from_str(cls, str: str) -> Self:
        """
        This expects the format `0.0.0.0:00'

        Where:

        0.0.0.0 = IPv4 Address
        :00     = Port Number
        """
        ip, port_str = str.split(":")
        if not cls.is_valid_ip(ip):
            raise ValueError(f"{ip} is not a valid IPv4")
        # formally I should check if port is between 0 and 64
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"{port_str} is not a valid port number")
        return cls(ip, port)


class TFTP_Mode(Enum):
    octet   = "octet"
    netascii = "netascii" # Nonfunctional as of yet

DEFAULT_MODE : TFTP_Mode = TFTP_Mode.octet

class TFTP_OpCode(IntEnum):
    RRQ = 1 # Read Request
    WRQ = 2 # Write Request
    DAT = 3 # Data
    ACK = 4 # Acknowledgement
    ERR = 5 # Error

    @staticmethod
    def is_opcode(n : int) -> bool:
        """
        As I like to use enums I created this to check if the integer value is containted in TFTP_OpCode enum
        """
        try:
            TFTP_OpCode(n)
            return True
        except ValueError:
            return False

class TFTP_Error(IntEnum):
    UNDEF_ERROR              = 0
    FILE_NOT_FOUND           = 1
    ACCESS_VIOLATION         = 2
    DISK_FULL_ALLOC_EXCEEDED = 3
    ILLEGAL_OPERATION        = 4
    UNKNOWN_TRANSFER_ID      = 5
    FILE_EXISTS              = 6
    NO_SUCH_USER             = 7

    @property
    def msg(self:Self) -> str:
        """
        Turns TFTP_Error values into user readable strings
        """
        return TFTP_Error.__err_msg(self)

    @classmethod
    def __err_msg(cls, value: Self) -> str:
        __ERROR_MSGS : Dict[TFTP_Error, str] = {
             TFTP_Error.UNDEF_ERROR              : "Undefined error."
            ,TFTP_Error.FILE_NOT_FOUND           : "File not found."
            ,TFTP_Error.ACCESS_VIOLATION         : "Access violation."
            ,TFTP_Error.DISK_FULL_ALLOC_EXCEEDED : "Disk full or allocation exceeded."
            ,TFTP_Error.ILLEGAL_OPERATION        : "Illegal TFTP operation."
            ,TFTP_Error.UNKNOWN_TRANSFER_ID      : "Unknown transfer ID."
            ,TFTP_Error.FILE_EXISTS              : "File already exists."
            ,TFTP_Error.NO_SUCH_USER             : "No such user"
        }
        ret = __ERROR_MSGS.get(value)
        if ret is None:
            raise ValueError("Impossible TFTP_Error value, stop trying to be smart")
        return ret
#: End Constants and Types

### Packing and unpacking

class Request():
    """
    Request it's just a function aggregator
    
    There is no reason to instantiate this class.
    
    All methods are either static or class methods.
    """

    def __init__(self) -> None:
        raise Exception("Unreachable: You shouldn't be calling this")
    
    @staticmethod
    def __pack_struct(fmt: str, op: TFTP_OpCode, *V : Any ) -> bytes:
        return struct.pack(fmt, op.value,*V)

    @staticmethod
    def _pack_rq(opcode: TFTP_OpCode, filename: str, mode: TFTP_Mode = DEFAULT_MODE) -> bytes:
        if not is_ascii_printable(filename):
            raise ValueError(f'Invalid filename {filename} is not ascii printable')
        if mode != TFTP_Mode.octet:
            raise ValueError(f'Invalid mode {mode}. Supported modes: octet.')
        pack_filename = byte_str(filename)
        pack_mode     = byte_str(mode.value)
        # "!H" -> unsigned int | size | "s"
        pack_format   = f"!H{len(pack_filename)}s{len(pack_mode)}s"
        return struct.pack(pack_format, opcode, pack_filename, pack_mode)
    
    # TODO: Refresh my understanding of TFTP packet formation 
    @staticmethod
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
    
    @staticmethod
    def unpack_opcode(packet: bytes) -> TFTP_OpCode:
        # ? Why [:2]
        # "!H" -> unsigned short  
        opcode, *_ = struct.unpack("!H", packet[:2]) 
        if TFTP_OpCode.is_opcode(opcode):
            return TFTP_OpCode(opcode)
        else:
            raise ValueError(f"Unrecognized opcode {opcode}")

    @classmethod
    def pack_dat(cls, block_num : int, data:bytes) -> bytes:
        if not 0 <= block_num <= MAX_BLOCK_NUM:
            raise ValueError(f'Invalid block number {block_num}')
        if len(data) > MAX_DATA_LEN:
            raise ValueError(f'Invalid data length {len(data)} ')
        # uint uint | size - bytes 
        fmt = f'!HH{len(data)}s'
        return cls.__pack_struct(fmt, TFTP_OpCode.DAT, block_num, data)
        # return struct.pack(fmt, TFTP_OpCode.DAT.value, block_num, data)
    
    @staticmethod
    def unpack_dat(packet: bytes) -> Tuple[int, bytes]:
        _, block_num = struct.unpack('!HH', packet[:4])
        return block_num, packet[4:]
    
    @classmethod
    def pack_rrq(cls, filename: str, mode: TFTP_Mode = DEFAULT_MODE) -> bytes:
        return cls._pack_rq(TFTP_OpCode.RRQ, filename, mode)
    
    @classmethod
    def unpack_rrq(cls, packet: bytes) -> Tuple[str, str]:
        return cls._unpack_rq(packet)
    
    @classmethod
    def pack_wrq(cls, filename: str, mode: TFTP_Mode = DEFAULT_MODE) -> bytes:
        return cls._pack_rq(TFTP_OpCode.WRQ, filename, mode)
    
    @classmethod
    def unpack_wrq(cls, packet: bytes) -> Tuple[str, str]:
        return cls._unpack_rq(packet)
    
    @classmethod
    def pack_ack(cls, block_number: int) -> bytes:
        if not 0 <= block_number and block_number <= MAX_BLOCK_NUM:
            raise ValueError(f"Invalid block number {block_number}")
        return cls.__pack_struct('!HH', TFTP_OpCode.ACK, block_number)
        #return struct.pack('!HH', TFTP_OpCode.ACK.value, block_number)
    
    @staticmethod
    def unpack_ack(packet: bytes) -> int:
        if len(packet) > 4:
            raise ValueError(f'Invalid packet length: {len(packet)}')
        return struct.unpack('!H', packet[2:4])[0] 
    
    @staticmethod
    def unpack_err(packet: bytes) -> Tuple[int, bytes]:
        _, error_num, error_msg = struct.unpack(f'!HH{len(packet)-4}s', packet)
        return error_num, error_msg[:-1]

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
    def __init__(self, error_code: TFTP_Error, error_msg: bytes):
        super().__init__(f'TFTP Error {error_code} :: Msg {error_code.msg} -> {error_msg.decode()}')
        self.error_code = error_code
        self.error_msg = error_msg.decode()

#: End: Errors and Exceptions

## Commmon Utils

def byte_str(s :str) -> bytes:
    return s.encode('utf-8') + b'\x00'

# TODO: Check if "str.isprintable()" could be used instead
def is_ascii_printable(txt :str) -> bool:
    return not set(txt) - set(printable)

#* Note this is a "maker" function, it exists just to compile the RegEx and create the "is_valid_hostname()" function
def _make_is_valid_hostname() -> Callable[[str], bool]:
    # Warning: Dark RegEx Magic
    #* Note: re.compile() seems to implement an internal cache so unless this regex
    #*        would change the cost of recompiling is just a dictionary lookup
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

def get_server_info(server_addr: str) -> Tuple[str, str]:
    """
    Returns the server ip and hostname for server_addr. 
    This param may either be an IP address, in which case this function tries to query its hostname, or vice-versa.
    This functions raises a ValueError exception if  the host name in server_addr is ill-formed, and raises NetworkError if we can't get
    an IP address for that host name.
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
            server_name: str = ''
    return server_ip, server_name

#: End: Commmon Utils

def get_file(server_addr: INET4_Address , filename: str):
    """
    RRQ a file given by filename from a remote TFTP server given by server_addr.
    """
    # Open "filename" for writting and in binary mode (wb)
    with open(os.path.abspath(filename), "wb") as file:
        # Create DGRAM socket 
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(INACTIVITY_TIMEOUT)
            # Send RRQ through socket
            rrq = Request.pack_rrq(filename)
            sock.sendto(rrq, server_addr.value)
            next_block_num = 1
            
            while True:
                # Wait for response 
                packet, new_serv_addr = sock.recvfrom(SOCKET_BUFFER_SIZE)
                # Extract opcode
                opcode = Request.unpack_opcode(packet)

                #(should be DAT)
                if opcode == TFTP_OpCode.DAT:
                    # Extract data and block num
                    block_num, data = Request.unpack_dat(packet)
                    # if block_num is correct 
                    if block_num != next_block_num:
                        raise ProtocolError(f"Invalid Block Number {block_num}")
                    
                    # save data in file
                    file.write(data)
                    # send ack
                    sock.sendto(Request.pack_ack((next_block_num)), new_serv_addr)
                    
                    # if the packet's data was smaller than max size then we know we're done
                    if len(data) < MAX_DATA_LEN:
                        break 
                # if Err 
                elif opcode == TFTP_OpCode.ERR:
                    # Raise and terminate RRQ
                    err_code, err_msg = Request.unpack_err(packet)
                    raise Err(TFTP_Error(err_code), err_msg)
                # else
                else:
                    # Raise protocol error
                    raise ProtocolError(f"Invalid opcode {opcode}")

def put_file(server_addr: INET4_Address , filename: str):
    with open(os.path.abspath(filename), "rb") as file:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(INACTIVITY_TIMEOUT)
            # Send RRQ through socket
            rrq = Request.pack_wrq(filename)
            sock.sendto(rrq, server_addr.value)
            current_block_num = 0
            file_size = os.stat(filename).st_size
            if file_size % 512 == 0:
                blocks = int((file_size / 512) + 1)
            else:
                blocks = math.ceil((file_size / 512))
            while True:
                # Wait for response 
                packet, new_serv_addr = sock.recvfrom(SOCKET_BUFFER_SIZE)
                # Extract opcode
                opcode = Request.unpack_opcode(packet)

                #(should be ACK)
                if opcode == TFTP_OpCode.ACK:
                    # Extract data and block num
                    block_num, _ = Request.unpack_dat(packet)
                    # if block_num is correct 
                    if block_num > current_block_num:
                        raise ProtocolError(f"Invalid Block Number {block_num}")
                    datum = b''
                    current_block_num += 1
                    if current_block_num <= blocks:
                        # read 512 bytes
                        datum = file.read(512)
                        sock.sendto(Request.pack_dat(current_block_num, datum), new_serv_addr)
                    else:
                        break
                    # Send DAT
                # if Err 
                elif opcode == TFTP_OpCode.ERR:
                    # Raise and terminate RRQ
                    err_code, err_msg = Request.unpack_err(packet)
                    raise Err(TFTP_Error(err_code), err_msg)
                # else
                else:
                    # Raise protocol error
                    raise ProtocolError(f"Invalid opcode {opcode}")

def get_dir(server: INET4_Address) -> str:
    raise NotImplementedError

def put_dir(server: INET4_Address) -> str:
    raise NotImplementedError

def main() -> None :
    # print()
    # print("____ RRQ ____")
    # rrq = pack_rrq('.ghci')
    # print(rrq)
    # filename, mode = unpack_rrq(rrq)
    # print(f"Filename: {filename} Mode: {mode}")
    # print()
    # print("____ WRQ ____")
    # wrq = pack_wrq('.ghci')
    # print(wrq)
    # filename, mode = unpack_wrq(wrq)
    # print(f"Filename: {filename} Mode: {mode}") 

    file_get = "test.yaml"
    srv = INET4_Address.from_tuple((get_server_info("open-sus")[0],69))
    os.system(f"rm -v {os.path.abspath(file_get)}")
    get_file(srv, file_get)
    os.system(f"bat {os.path.abspath(file_get)}")
    # I don't get why "demo.md" works but "../demo.md" doesn't 
    #  especially when "../test.yaml" has the second form
    #  the other file open, changed working dir
    # I figured it out, he can get ../test.yaml but in lands not in here but in the 
    #   parent folder
    # But I can't send the file from the parent folder since the file
    #   is in the current directory
    file_put = "demo.md"
    put_file(srv, file_put)



if __name__ == "__main__":
    main()
