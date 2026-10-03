#!/usr/bin/env python3
"""Verify a kpramdisk-patched init_boot image against the stock one.

Decodes both ramdisks with the system `lz4` CLI (independent reference
decoder), parses the newc archives and compares them entry by entry.
"""
import hashlib
import struct
import subprocess
import sys
import tempfile
import os

PAGE = 4096


def read_ramdisk(img_path, out_path):
    """boot_img_hdr: magic @0 (8), kernel_size @8, ramdisk_size @12.
    v3/v4 put both payloads behind one page and pad each to the page size."""
    data = open(img_path, 'rb').read()
    kernel_size, ramdisk_size = struct.unpack_from('<II', data, 8)
    ram_off = PAGE + ((kernel_size + PAGE - 1) // PAGE) * PAGE
    ram = data[ram_off:ram_off + ramdisk_size]
    with open(out_path, 'wb') as fh:
        fh.write(ram)
    return _lz4_decompress(out_path)


def _lz4_decompress(path):
    import shutil
    lz4 = shutil.which('lz4')
    if lz4 is None:
        raise SystemExit('lz4 CLI not found (needed as the reference decoder)')
    p = subprocess.run([lz4, '-d', '-c', path], capture_output=True)
    if p.returncode != 0 or not p.stdout:
        raise SystemExit('lz4 -d failed: %s' % p.stderr.decode(errors='replace'))
    return p.stdout


def parse_cpio(blob):
    entries = []
    off = 0
    while True:
        hdr = blob[off:off + 110]
        if len(hdr) < 110 or hdr[:6] != b'070701':
            raise SystemExit('bad cpio magic at %d: %r' % (off, hdr[:6]))
        fields = [int(hdr[6 + i * 8:6 + (i + 1) * 8], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        name = blob[off + 110:off + 110 + namesize - 1].decode()
        pos = off + 110 + namesize
        pos = (pos + 3) & ~3
        data = blob[pos:pos + size]
        pos = (pos + size + 3) & ~3
        if name == 'TRAILER!!!':
            break
        entries.append({
            'name': name,
            'mode': oct(mode),
            'size': size,
            'sha': hashlib.sha256(data).hexdigest(),
            'data': data,
        })
        off = pos
    return entries


def main():
    stock, patched, kpinit, ko, params = sys.argv[1:6]
    tmp = tempfile.mkdtemp()
    old = parse_cpio(read_ramdisk(stock, os.path.join(tmp, 's.lz4')))
    new = parse_cpio(read_ramdisk(patched, os.path.join(tmp, 'p.lz4')))
    print('stock entries   : %d' % len(old))
    print('patched entries : %d' % len(new))

    by_name = {e['name']: e for e in new}
    ok = True

    # 1. every original entry must survive byte-identically (except /init)
    for e in old:
        if e['name'] == 'init':
            continue
        n = by_name.get(e['name'])
        if n is None:
            print('MISSING  %s' % e['name'])
            ok = False
        elif n['sha'] != e['sha'] or n['mode'] != e['mode']:
            print('CHANGED  %s' % e['name'])
            ok = False

    # 2. /init must have been renamed to /init.real with identical bytes
    ireal = by_name.get('init.real')
    iold = [e for e in old if e['name'] == 'init'][0]
    if ireal is None:
        print('MISSING  init.real')
        ok = False
    else:
        same = ireal['sha'] == iold['sha']
        print('init -> init.real identical : %s (%d bytes)' % (same, iold['size']))
        ok &= same

    # 3. the injected entries must match their source files
    for name, path, expect_mode in (('init', kpinit, '0o100755'),
                                    ('kernelpatch.ko', ko, '0o100755'),
                                    ('kp_config', None, '0o100644')):
        e = by_name.get(name)
        if e is None:
            print('MISSING  %s' % name)
            ok = False
            continue
        if path is not None:
            src = hashlib.sha256(open(path, 'rb').read()).hexdigest()
            same = src == e['sha']
            print('%-16s == %s : %s (%d bytes)' % (name, os.path.basename(path), same, e['size']))
            ok &= same
        else:
            val = e['data'].rstrip(b'\x00')
            same = val == params.encode()
            print('%-16s == b\'%s\' : %s (mode %s)' % (name, params, same, e['mode']))
            ok &= same
        if e['mode'] != expect_mode:
            print('  ! mode %s, expected %s' % (e['mode'], expect_mode))
            ok = False

    # 4. the AVB footer must point at a vbmeta block behind the new ramdisk
    data = open(patched, 'rb').read()
    footer = data[-64:]
    vb_off, vb_size = struct.unpack_from('>QQ', footer, 20)
    (ramdisk_size,) = struct.unpack_from('<I', data, 8)
    avb_ok = footer[:4] == b'AVBf' and data[vb_off:vb_off + 4] == b'AVB0' \
        and vb_off >= PAGE + ramdisk_size
    print('avb footer -> %d bytes @ %d, after ramdisk : %s' % (vb_size, vb_off, avb_ok))
    ok &= avb_ok

    print('RESULT: %s' % ('ALL GOOD' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
