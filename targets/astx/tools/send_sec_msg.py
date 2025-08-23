#!/usr/bin/env python3
import struct
import sys

import sysv_ipc

KEY = 0x075CA61F
MTYPE = 0x14

# Opcodes seen in processMessageQueue()
OP_EUPDATECONF = 0x0A
OP_SEC_LEVEL = 0x0C
OP_EXIT_FIREWALL = 0x0E
OP_IO_BOUND = 0x12
OP_TRAY_PID = 0x16
OP_APPLY_18 = 0x18
OP_APPLY_19 = 0x19
OP_APPLY_1A = 0x1A

MTEXT_LEN = 0x58C  # match daemon's msgrcv size


def send_sec_level(level: int):
    q = sysv_ipc.MessageQueue(KEY)  # attaches existing queue
    buf = bytearray(MTEXT_LEN)
    struct.pack_into("<I", buf, 8, OP_SEC_LEVEL)  # opcode
    struct.pack_into("<I", buf, 20, level)  # new sec level (0/1/2)
    q.send(bytes(buf), block=False, type=MTYPE)
    print(f"sent SEC_LEVEL = {level}")


if __name__ == "__main__":
    lvl = 1
    if len(sys.argv) == 2:
        lvl = int(sys.argv[1])
    assert lvl in (0, 1, 2), "level must be 0, 1, or 2"
    send_sec_level(lvl)
