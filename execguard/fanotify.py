"""fanotify ctypes bindings, constants, and fd management."""

import ctypes
import logging
import os
import struct
import sys

__all__ = [
    "FAN_CLASS_CONTENT", "FAN_CLOEXEC", "FAN_OPEN_EXEC_PERM",
    "FAN_MARK_ADD", "FAN_MARK_INODE", "FAN_ALLOW", "FAN_DENY",
    "AT_FDCWD", "O_RDONLY", "O_LARGEFILE",
    "EVENT_FMT", "EVENT_SIZE", "RESP_FMT",
    "make_fan_fd", "setup_watches",
]

# fanotify constants — see fanotify(7) and include/uapi/linux/fanotify.h
FAN_CLASS_CONTENT  = 0x00000004  # report content/permission events (required for PERM events)
FAN_CLOEXEC        = 0x00000001  # set close-on-exec on the returned fanotify fd
FAN_OPEN_EXEC_PERM = 0x00040000  # intercept exec-open; kernel blocks caller until we respond
FAN_MARK_ADD       = 0x00000001  # add to the mark set (vs remove)
FAN_MARK_INODE     = 0x00000000  # mark a specific inode (vs mount or filesystem)
FAN_ALLOW          = 0x01        # permit the exec
FAN_DENY           = 0x02        # block the exec (EPERM returned to caller)
AT_FDCWD           = getattr(os, "AT_FDCWD", -100)  # -100 per Linux <fcntl.h>; os.AT_FDCWD not always present
O_RDONLY           = os.O_RDONLY
O_LARGEFILE        = os.O_LARGEFILE

# struct fanotify_event_metadata { u32 event_len, u8 vers, u8 reserved, u16 metadata_len, u64 mask, s32 fd, s32 pid }
# struct.pack/unpack format: = native order no padding; I=u32 B=u8 B=u8 H=u16 Q=u64 i=s32 i=s32
EVENT_FMT  = "=IBBHQii"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
# struct fanotify_response { s32 fd, u32 response }
# struct.pack/unpack format: = native order no padding; i=s32 I=u32
RESP_FMT   = "=iI"

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.fanotify_init.restype  = ctypes.c_int
libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
libc.fanotify_mark.restype  = ctypes.c_int
libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                ctypes.c_int, ctypes.c_char_p]

log = logging.getLogger("execguard")


def make_fan_fd() -> int:
    fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE)
    if fd < 0:
        sys.exit(f"fanotify_init: {os.strerror(ctypes.get_errno())}")
    return fd


def setup_watches(fan_fd: int, paths: list[str]) -> None:
    for path in paths:
        ret = libc.fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_INODE,
                                  FAN_OPEN_EXEC_PERM, AT_FDCWD, path.encode())
        if ret < 0:
            log.warning(f"fanotify_mark failed for {path}: {os.strerror(ctypes.get_errno())}")
