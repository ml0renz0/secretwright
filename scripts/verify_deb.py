#!/usr/bin/env python3
"""Inspect the project's bounded Debian packages without extracting files."""

import hashlib
import re
import tarfile
import zlib


MAX_DEB = 128 << 20
MAX_BINARY = 128 << 20
MAX_DOCUMENT = 4 << 20
MAX_DATA_TAR = MAX_BINARY + 2 * MAX_DOCUMENT + (1 << 20)
MAX_CONTROL_TAR = 1 << 20
MAX_CONTROL = 64 << 10
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
                    r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
                    r'(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?')
PAYLOAD = {
    'usr/bin/secretwright': (0o755, MAX_BINARY),
    'usr/share/doc/secretwright/README.md': (0o644, MAX_DOCUMENT),
    'usr/share/doc/secretwright/copyright': (0o644, MAX_DOCUMENT),
}
DATA_DIRECTORIES = {'', 'usr', 'usr/bin', 'usr/share', 'usr/share/doc', 'usr/share/doc/secretwright'}
CONTROL_FILES = {'control': (0o644, MAX_CONTROL), 'md5sums': (0o644, MAX_CONTROL)}


class VerificationError(ValueError):
    """Diagnostics intentionally omit package paths and input contents."""


def require(condition):
    if not condition:
        raise VerificationError('invalid Debian package')


def debian_version(version):
    require(isinstance(version, str) and 0 < len(version) <= 128)
    match = SEMVER.fullmatch(version)
    require(match is not None)
    require(not any(part.isdigit() and len(part) > 1 and part[0] == '0'
                    for part in (match.group(4) or '').split('.')))
    core, plus, metadata = version.partition('+')
    return core.replace('-', '~', 1) + plus + metadata


def deb_name(version, architecture):
    require(architecture in ('amd64', 'arm64'))
    return f'secretwright_{debian_version(version)}_{architecture}.deb'


def deb_sbom_name(version, architecture):
    return deb_name(version, architecture) + '.spdx.json'


def number(field, radix=10):
    text = field.decode('ascii').strip(' ')
    require(re.fullmatch(r'[0-7]+' if radix == 8 else r'[0-9]+', text) is not None)
    value = int(text, radix)
    require(value <= (1 << 63) - 1)
    return value


def ar_members(body):
    require(isinstance(body, bytes) and 0 < len(body) <= MAX_DEB and body.startswith(b'!<arch>\n'))
    members = []
    position = 8
    while position < len(body):
        require(len(members) < 3 and position + 60 <= len(body))
        header = body[position:position + 60]
        require(header[58:] == b'`\n')
        name = header[:16].decode('ascii').rstrip(' ')
        if name.endswith('/'):
            name = name[:-1]
        number(header[16:28])
        require(number(header[28:34]) == 0 and number(header[34:40]) == 0)
        require(number(header[40:48], 8) in (0o644, 0o100644))
        size = number(header[48:58])
        require(0 < size <= MAX_DEB and position + 60 + size <= len(body))
        members.append((name, body[position + 60:position + 60 + size]))
        position += 60 + size
        if size % 2:
            require(body[position:position + 1] == b'\n')
            position += 1
    require(position == len(body))
    require([name for name, _ in members] == ['debian-binary', 'control.tar.gz', 'data.tar.gz'])
    require(members[0][1] == b'2.0\n')
    return members[1][1], members[2][1]


def gunzip(body, maximum):
    source = zlib.decompressobj(16 + zlib.MAX_WBITS)
    result = source.decompress(body, maximum + 1)
    require(len(result) <= maximum and source.eof and not source.unconsumed_tail and not source.unused_data)
    return result


def tar_contents(compressed, maximum, files, directories):
    body = gunzip(compressed, maximum)
    require(len(body) % 512 == 0)
    position = 0
    contents = {}
    seen = set()
    while position + 512 <= len(body):
        header = body[position:position + 512]
        if not any(header):
            require(len(body) - position >= 1024 and not any(body[position:]))
            break
        require(len(seen) < 32)
        item = tarfile.TarInfo.frombuf(header, encoding='utf-8', errors='strict')
        require(item.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE))
        require(item.uid == 0 and item.gid == 0 and not item.linkname)
        name = item.name
        if name.startswith('./'):
            name = name[2:]
        if name == '.':
            name = ''
        if item.isdir() and name.endswith('/'):
            name = name[:-1]
        # TarInfo normalizes directory slashes; validate the original spelling
        # too so an absolute '/' cannot become the allowed root directory.
        raw_name = header[:100].split(b'\0', 1)[0].decode('utf-8')
        if header[257:263] == b'ustar\0':
            prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8')
            if prefix:
                raw_name = prefix + '/' + raw_name
        if name:
            spellings = {name, './' + name}
            if item.isdir():
                spellings |= {name + '/', './' + name + '/'}
            require(raw_name in spellings)
        else:
            require(item.isdir() and raw_name in ('.', './'))
        require(name not in seen)
        seen.add(name)
        if item.isdir():
            require(name in directories and item.mode == 0o755 and item.size == 0)
        else:
            require(name in files)
            mode, limit = files[name]
            require(item.mode == mode and 0 < item.size <= limit)
            require(position + 512 + item.size <= len(body))
            contents[name] = body[position + 512:position + 512 + item.size]
        position += 512 + ((item.size + 511) // 512) * 512
    else:
        require(False)
    require(set(contents) == set(files) and seen == set(files) | directories)
    return contents


def control_fields(body, version, architecture):
    text = body.decode('utf-8')
    require('\r' not in text and '\0' not in text and text.endswith('\n'))
    fields = {}
    previous = None
    paragraph_ended = False
    for line in text.splitlines():
        if not line:
            paragraph_ended = True
            continue
        require(not paragraph_ended)
        if line.startswith((' ', '\t')):
            require(previous is not None)
            fields[previous] += '\n' + line[1:]
            continue
        key, colon, value = line.partition(':')
        require(colon and re.fullmatch('[A-Za-z][A-Za-z0-9-]*', key) is not None)
        key = key.lower()
        require(key not in fields)
        fields[key] = value.lstrip(' ')
        previous = key
    allowed = {'package', 'version', 'architecture', 'maintainer', 'description', 'installed-size',
               'depends', 'section', 'priority', 'homepage'}
    require(set(fields) <= allowed)
    require(fields.get('package') == 'secretwright' and fields.get('version') == debian_version(version))
    require(fields.get('architecture') == architecture and fields.get('depends') == 'ca-certificates')
    require(bool(fields.get('maintainer', '').strip()) and bool(fields.get('description', '').strip()))
    size = fields.get('installed-size', '')
    require(re.fullmatch('[1-9][0-9]{0,8}', size) is not None)
    if 'section' in fields:
        require(fields['section'] == 'utils')
    if 'priority' in fields:
        require(fields['priority'] == 'optional')
    if 'homepage' in fields:
        require(fields['homepage'] == 'https://github.com/ml0renz0/secretwright')


def verify_md5sums(body, payload):
    lines = body.decode('ascii').splitlines()
    require(len(lines) == len(payload))
    seen = set()
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{32})  ([A-Za-z0-9_./-]+)', line)
        require(match is not None)
        digest, name = match.groups()
        require(name in payload and name not in seen)
        seen.add(name)
        # md5sums is dpkg's local integrity inventory; release authentication uses SHA-256.
        require(hashlib.md5(payload[name], usedforsecurity=False).hexdigest() == digest)
    require(seen == set(payload))


def verify_deb(body, version, architecture):
    """Return the binary only after all metadata and container contents pass.

    The release verifier additionally checks its ELF architecture and compares
    these bytes with the independently verified Linux archive executable.
    """
    try:
        deb_name(version, architecture)
        control, data = ar_members(body)
        control = tar_contents(control, MAX_CONTROL_TAR, CONTROL_FILES, {''})
        payload = tar_contents(data, MAX_DATA_TAR, PAYLOAD, DATA_DIRECTORIES)
        control_fields(control['control'], version, architecture)
        verify_md5sums(control['md5sums'], payload)
        require(payload['usr/share/doc/secretwright/copyright'].startswith(b'MIT License'))
        return payload['usr/bin/secretwright']
    except VerificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError,
            zlib.error, OverflowError):
        raise VerificationError('invalid Debian package') from None
