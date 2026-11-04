#!/usr/bin/env python3
"""Local, standard-library connector inventory, preview, and guarded XML updates."""
from __future__ import annotations

import argparse
import codecs
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET

ENVIRONMENTS = ('unknown', 'dev', 'test', 'sit', 'uat', 'prod')
SECTION = ('configuration', 'IntegrationServiceCustomerConfigurationSection', 'LocalConnectors')


class ConfigError(Exception):
    """A safe, user-facing error which never includes source XML or properties."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def xml_root(text):
    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', text, re.I):
        raise ConfigError('DTD/entity declarations are not supported. No changes made.')
    try:
        return ET.fromstring(text)
    except (ET.ParseError, ValueError):
        raise ConfigError('XML is not well formed; source details are withheld to protect secrets.') from None


def decode(data):
    for bom, encoding in ((codecs.BOM_UTF8, 'utf-8'),
                          (codecs.BOM_UTF16_LE, 'utf-16-le'),
                          (codecs.BOM_UTF16_BE, 'utf-16-be')):
        if data.startswith(bom):
            return data[len(bom):].decode(encoding), encoding, bom
    if data.startswith(b'\x00<'):
        return data.decode('utf-16-be'), 'utf-16-be', b''
    if data.startswith(b'<\x00'):
        return data.decode('utf-16-le'), 'utf-16-le', b''
    declaration = re.match(br'\s*<\?xml\b[^?]*encoding\s*=\s*[\'"]([^\'"]+)', data[:512])
    encoding = declaration.group(1).decode('ascii') if declaration else 'utf-8'
    try:
        info = codecs.lookup(encoding)
        if info.name not in ('utf-8', 'ascii', 'iso8859-1', 'cp1252'):
            raise ConfigError('Unsupported XML encoding. Use UTF-8, UTF-16, Latin-1 or Windows-1252.')
        return data.decode(encoding), encoding, b''
    except (UnicodeError, LookupError):
        raise ConfigError('Cannot decode the XML encoding safely.') from None


class WindowsSecurity:
    """Native owner/group/DACL copy and verification; fails closed on unsupported access."""
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.c, self.w = ctypes, wintypes
        try:
            self.api = ctypes.WinDLL('advapi32', use_last_error=True)
        except (AttributeError, OSError):
            raise ConfigError('Windows native security APIs are unavailable. Apply is refused.') from None
        void = ctypes.c_void_p
        boolean, dword = wintypes.BOOL, wintypes.DWORD
        functions = {
            'GetFileSecurityW': ([wintypes.LPCWSTR, dword, void, dword, ctypes.POINTER(dword)], boolean),
            'SetFileSecurityW': ([wintypes.LPCWSTR, dword, void], boolean),
            'GetSecurityDescriptorOwner': ([void, ctypes.POINTER(void), ctypes.POINTER(boolean)], boolean),
            'GetSecurityDescriptorGroup': ([void, ctypes.POINTER(void), ctypes.POINTER(boolean)], boolean),
            'GetSecurityDescriptorDacl': ([void, ctypes.POINTER(boolean), ctypes.POINTER(void), ctypes.POINTER(boolean)], boolean),
            'GetSecurityDescriptorControl': ([void, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(dword)], boolean),
            'GetLengthSid': ([void], dword),
            'IsValidSecurityDescriptor': ([void], boolean),
        }
        for name, (args, result) in functions.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result

    def _check(self, success):
        if not success:
            raise ConfigError('Windows owner/group/DACL access or verification failed. No unsafe replacement will be attempted; ask an administrator to review permissions.')

    def read(self, path):
        c, w = self.c, self.w
        needed = w.DWORD()
        self.api.GetFileSecurityW(str(path), 7, None, 0, c.byref(needed))
        if not 0 < needed.value <= 16 * 1024 * 1024:
            self._check(False)
        buffer = c.create_string_buffer(needed.value)
        self._check(self.api.GetFileSecurityW(str(path), 7, buffer, len(buffer), c.byref(needed)))
        raw = bytes(buffer[:needed.value])
        return raw, self.signature(raw)

    def signature(self, raw):
        c, w = self.c, self.w
        buffer = c.create_string_buffer(raw)
        self._check(self.api.IsValidSecurityDescriptor(buffer))
        parts = []
        for getter in (self.api.GetSecurityDescriptorOwner, self.api.GetSecurityDescriptorGroup):
            pointer, defaulted = c.c_void_p(), w.BOOL()
            self._check(getter(buffer, c.byref(pointer), c.byref(defaulted)))
            self._check(bool(pointer.value))
            length = self.api.GetLengthSid(pointer)
            self._check(0 < length <= 4096)
            parts.append(c.string_at(pointer, length))
        present, defaulted, acl = w.BOOL(), w.BOOL(), c.c_void_p()
        self._check(self.api.GetSecurityDescriptorDacl(buffer, c.byref(present), c.byref(acl), c.byref(defaulted)))
        # Absent/null DACLs grant unrestricted access and cannot protect backup payloads.
        self._check(bool(present.value and acl.value))
        header = c.string_at(acl, 8)
        length = int.from_bytes(header[2:4], 'little')
        self._check(8 <= length <= 65535)
        parts.append(c.string_at(acl, length))
        control, revision = w.WORD(), w.DWORD()
        self._check(self.api.GetSecurityDescriptorControl(buffer, c.byref(control), c.byref(revision)))
        parts.append(bool(control.value & 0x1000))
        return tuple(parts)

    def apply(self, path, security):
        raw, expected = security
        buffer = self.c.create_string_buffer(raw)
        protection = 0x80000000 if expected[-1] else 0x20000000
        self._check(self.api.SetFileSecurityW(str(path), 7 | protection, buffer))
        _, actual = self.read(path)
        self._check(actual == expected)


@dataclass(frozen=True)
class Token:
    kind: str
    start: int
    end: int
    name: str = ''
    empty: bool = False


def tokens(text):
    """Lex XML boundaries, respecting attribute quotes, comments, CDATA and PIs."""
    pos = 0
    while True:
        start = text.find('<', pos)
        if start < 0:
            return
        if text.startswith('<!--', start):
            end = text.find('-->', start + 4)
            kind, offset = 'comment', 3
        elif text.startswith('<![CDATA[', start):
            end = text.find(']]>', start + 9)
            kind, offset = 'cdata', 3
        elif text.startswith('<?', start):
            end = text.find('?>', start + 2)
            kind, offset = 'pi', 2
        else:
            end, quote = start + 1, None
            while end < len(text):
                ch = text[end]
                if quote:
                    if ch == quote:
                        quote = None
                elif ch in '\'"':
                    quote = ch
                elif ch == '>':
                    break
                end += 1
            kind, offset = 'tag', 1
        if end < 0 or end >= len(text):
            raise ConfigError('Unterminated XML token; no changes made.')
        stop = end + offset
        if kind == 'tag':
            raw = text[start:stop]
            m = re.match(r'<(/?)([^\s/>]+)', raw)
            if not m or m.group(2).startswith('!'):
                raise ConfigError('Unsupported XML declaration.')
            yield Token('end' if m.group(1) else 'start', start, stop,
                        m.group(2), raw.rstrip().endswith('/>'))
        else:
            yield Token(kind, start, stop)
        pos = stop


def direct_spans(text):
    """Return parsed top-level connector spans in an otherwise valid comment fragment."""
    try:
        root = xml_root('<Fragment>' + text + '</Fragment>')
    except ConfigError:
        return None
    descendants = list(root.iter('LocalConnector'))
    if len(descendants) != sum(c.tag == 'LocalConnector' for c in root):
        return None
    stack, spans, begin = [], [], None
    for t in tokens(text):
        if t.kind == 'start':
            if not stack and t.name == 'LocalConnector':
                begin = t.start
            if not t.empty:
                stack.append(t.name)
            elif not stack and t.name == 'LocalConnector':
                spans.append((t.start, t.end))
        elif t.kind == 'end':
            if not stack or stack[-1] != t.name:
                return None
            stack.pop()
            if not stack and t.name == 'LocalConnector':
                spans.append((begin, t.end))
    return spans


def vendor_for(identifier):
    for prefix in ('Bloomberg', 'ICE360', 'ICE', 'SWIB', 'FactSet', 'MSCI', 'Reuters', 'Aladdin'):
        if identifier.casefold().startswith(prefix.casefold()):
            return prefix
    base = re.sub(r'(?:Inbound|Outbound|In|Out)$', '', identifier, flags=re.I)
    return base or identifier


@dataclass(frozen=True)
class Connector:
    key: str
    identifier: str
    vendor: str
    transport: str
    direction: str
    type_name: str
    enabled: bool
    start: int
    end: int
    comment: tuple | None
    line: int
    supported: bool

    def public(self):
        return {k: getattr(self, k) for k in ('key', 'identifier', 'vendor', 'transport',
                                            'direction', 'type_name', 'enabled', 'line', 'supported')}


class Document:
    def __init__(self, data, source=''):
        self.data, self.source = data, str(source)
        self.sha256 = digest(data)
        try:
            self.text, self.encoding, self.bom = decode(data)
        except UnicodeError:
            raise ConfigError('Cannot decode XML safely.') from None
        if self.encode(self.text) != data:
            raise ConfigError('XML encoding does not round-trip byte-for-byte.')
        root = xml_root(self.text)
        if root.tag != 'configuration' or len(root.findall('./IntegrationServiceCustomerConfigurationSection/LocalConnectors')) != 1:
            raise ConfigError('Expected exactly one configuration/IntegrationServiceCustomerConfigurationSection/LocalConnectors.')
        self.connectors, self.warnings = [], []
        if os.name == 'nt':
            self.warnings.append('Windows Apply requires native owner/group/DACL copy and verification for backup and replacement. It fails closed if permissions cannot be preserved. Use a secured directory; SACL/audit labels and every filesystem-specific attribute are not guaranteed.')
        self.production = bool(re.search(r'(?i)(?:swibp1|(?:^|[^a-z])prod(?:uction)?(?:[^a-z]|$))', self.source + '\n' + self.text))
        if self.production:
            self.warnings.append('Production labels or paths detected (including SWIBP1/Prod). Environment selection is still required.')
        if re.search(r'(?i)never\s+enable|prod\s+only', self.text):
            self.warnings.append('Source contains production-only / Never enable safeguards. ICE/ICE360 outbound cannot be enabled outside prod.')
        self._scan()
        self.by_key = {c.key: c for c in self.connectors}
        self._unique()

    def encode(self, text):
        return self.bom + text.encode(self.encoding)

    def _add(self, start, end, enabled, comment=None):
        element = xml_root(self.text[start:end])
        identifier = element.get('identifier', '')
        if not identifier:
            raise ConfigError('A connector has no identifier; safe targeting is impossible.')
        type_name = element.get('type', '').split(',')[0].split('.')[-1]
        properties = {p.get('name', '').casefold(): p.get('value', '')
                      for p in element.findall('./Properties/Property')}
        if type_name in ('BatchFileSystemInConnector', 'FileSystemOutConnector'):
            transport = 'Filesystem'
        elif type_name in ('FtpInConnector', 'FtpOutConnector'):
            sftp = properties.get('usesftp', '').strip().casefold()
            transport = 'SFTP' if sftp == 'true' else 'FTP' if sftp == 'false' else 'FTP/Unknown'
        else:
            transport = 'Unknown'
        direction = element.get('kind', 'Unknown')
        line = self.text.count('\n', 0, start) + 1
        identity = '\0'.join((identifier, type_name, direction, str(start)))
        key = f'L{line}-{digest(identity.encode())[:12]}'
        raw = self.text[start:end]
        supported = enabled and '--' not in raw or not enabled
        self.connectors.append(Connector(key, identifier, vendor_for(identifier), transport,
                                         direction, type_name, enabled, start, end,
                                         comment, line, supported))

    def _scan(self):
        stack, active_start, sections = [], None, 0
        for t in tokens(self.text):
            if t.kind == 'comment' and tuple(stack) == SECTION:
                body = self.text[t.start + 4:t.end - 3]
                spans = direct_spans(body)
                if spans is None:
                    if 'LocalConnector' in body:
                        self.warnings.append(f'Unsupported/ambiguous disabled block near line {self.text.count(chr(10), 0, t.start) + 1}; left untouched.')
                    continue
                for a, b in spans:
                    self._add(t.start + 4 + a, t.start + 4 + b, False, (t.start, t.end))
            elif t.kind == 'start':
                if tuple(stack) == SECTION and t.name == 'LocalConnector':
                    active_start = t.start
                    if t.empty:
                        self._add(t.start, t.end, True)
                        active_start = None
                if not t.empty:
                    stack.append(t.name)
            elif t.kind == 'end':
                if tuple(stack) == SECTION + ('LocalConnector',) and t.name == 'LocalConnector':
                    self._add(active_start, t.end, True)
                    active_start = None
                if stack:
                    stack.pop()
        self.connectors.sort(key=lambda c: c.start)

    def _unique(self):
        counts = Counter(c.identifier.casefold() for c in self.connectors if c.enabled)
        if any(n > 1 for n in counts.values()):
            raise ConfigError('Duplicate active connector identifiers. Explicitly repair the source before using this tool.')

    def preview(self, changes, environment, acknowledge_production=False):
        if environment not in ENVIRONMENTS or environment == 'unknown':
            raise ConfigError('Choose dev, test, sit, uat or prod before making edits.')
        if not changes:
            raise ConfigError('No staged changes.')
        if (self.production or environment == 'prod') and not acknowledge_production:
            raise ConfigError('Explicit production acknowledgement is required for a production-labelled file or prod environment.')
        selected = []
        for key, enabled in changes.items():
            c = self.by_key.get(key)
            if c is None:
                raise ConfigError('Unknown/stale definition key. Reload and rebuild the plan.')
            if not isinstance(enabled, bool) or c.enabled == enabled:
                raise ConfigError('Plan contains a no-op or invalid target status.')
            if not c.supported:
                raise ConfigError(f'{c.key}: disabling an element containing internal comments or double-hyphens is unsupported. Have an administrator edit it safely.')
            if enabled and c.direction.casefold() == 'outbound' and c.identifier.upper().startswith('ICE') and environment != 'prod':
                raise ConfigError('ICE/ICE360 outbound is PROD only. It cannot be enabled in this environment.')
            selected.append(c)
        enabled_ids = Counter(c.identifier.casefold() for c in self.connectors if changes.get(c.key, c.enabled))
        if any(n > 1 for n in enabled_ids.values()):
            raise ConfigError('Enabling this alternative duplicates an active identifier. Explicitly stage Disable for the active counterpart; preview must show both changes.')
        edits, groups = [], {}
        for c in selected:
            if c.enabled:
                edits.append((c.start, c.end, '<!--' + self.text[c.start:c.end] + '-->'))
            else:
                groups.setdefault(c.comment, []).append(c)
        for (start, end), cs in groups.items():
            pos, pieces = start + 4, []
            for c in sorted(cs, key=lambda x: x.start):
                pieces.extend(('<!--' + self.text[pos:c.start] + '-->', self.text[c.start:c.end]))
                pos = c.end
            pieces.append('<!--' + self.text[pos:end - 3] + '-->')
            edits.append((start, end, ''.join(pieces)))
        text = self.text
        for start, end, value in sorted(edits, reverse=True):
            text = text[:start] + value + text[end:]
        data = self.encode(text)
        updated = Document(data, self.source)
        before = Counter(c.identifier.casefold() for c in self.connectors)
        after = Counter(c.identifier.casefold() for c in updated.connectors)
        if before != after or len(updated.connectors) != len(self.connectors):
            raise ConfigError('Inventory changed unexpectedly; refusing the edit.')
        expected = Counter((c.identifier, c.type_name, c.direction, changes.get(c.key, c.enabled)) for c in self.connectors)
        actual = Counter((c.identifier, c.type_name, c.direction, c.enabled) for c in updated.connectors)
        if expected != actual:
            raise ConfigError('Preview verification failed; no write attempted.')
        return data, [{'key': c.key, 'identifier': c.identifier, 'transport': c.transport,
                       'direction': c.direction, 'from': 'enabled' if c.enabled else 'disabled',
                       'to': 'enabled' if changes[c.key] else 'disabled'} for c in selected]


def guarded_path(path):
    p = Path(os.path.abspath(os.path.expanduser(str(path))))
    for part in (p, *p.parents):
        try:
            st = part.lstat()
        except OSError:
            raise ConfigError('Config path or parent is inaccessible.') from None
        if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
            raise ConfigError('Symlinks / Windows reparse points are not supported. Select the direct secured path.')
    if not p.is_file():
        raise ConfigError('Select a regular configuration file.')
    return p


def identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, stat.S_IMODE(st.st_mode),
            getattr(st, 'st_uid', None), getattr(st, 'st_gid', None), st.st_nlink)


def safe_read(path):
    for attempt in range(3):
        try:
            return _read_once(path)
        except ConfigError as exc:
            if not str(exc).startswith('File changed while') or attempt == 2:
                raise


def _read_once(path):
    p = guarded_path(path)
    fd = None
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or identity(before) != identity(p.stat()):
            raise ConfigError('File changed while opening. Reload it.')
        with os.fdopen(fd, 'rb') as f:
            fd = None
            data = f.read()
            after = os.fstat(f.fileno())
        if identity(before) != identity(after) or identity(after) != identity(p.stat()):
            raise ConfigError('File changed while reading. Reload it.')
        return p, data, after
    except OSError:
        raise ConfigError('Cannot read the selected file. Check local access permissions.') from None
    finally:
        if fd is not None:
            os.close(fd)


class Session:
    def __init__(self, path):
        self.path, data, self.stat = safe_read(path)
        self.document = Document(data, self.path)

    def check_current(self):
        p, data, st = safe_read(self.path)
        if identity(st) != identity(self.stat) or digest(data) != self.document.sha256:
            raise ConfigError('STALE file: source changed since opening. Reload and rebuild the plan; nothing was overwritten.')

    def plan(self, changes, environment, acknowledge=False):
        data, rows = self.document.preview(changes, environment, acknowledge)
        return {'format': 1, 'path': str(self.path), 'source_sha256': self.document.sha256,
                'environment': environment, 'acknowledge_production': bool(acknowledge),
                'changes': dict(changes), 'preview': rows,
                'result_sha256': digest(data)}

    def apply(self, plan, writers_coordinated=False):
        if not writers_coordinated:
            raise ConfigError('Confirm all services, editors and deployment/config writers are stopped or coordinated before Apply. The cooperative lock cannot protect against uncooperative writers.')
        if plan.get('format') != 1 or plan.get('source_sha256') != self.document.sha256 or plan.get('path') != str(self.path):
            raise ConfigError('Plan belongs to another file or snapshot. Rebuild the plan.')
        if not isinstance(plan.get('changes'), dict):
            raise ConfigError('Invalid plan changes.')
        data, rows = self.document.preview(plan['changes'], plan.get('environment'), plan.get('acknowledge_production') is True)
        if plan.get('result_sha256') != digest(data) or plan.get('preview') != rows:
            raise ConfigError('Plan preview or result hash changed. Rebuild and review the plan.')
        self.check_current()
        self._check_security_metadata(self.path)
        if self.stat.st_nlink != 1:
            raise ConfigError('Hard-linked config files are unsupported. Select a standalone file with administrator-approved security settings.')
        mode = stat.S_IMODE(self.stat.st_mode)
        if mode & 0o7000:
            raise ConfigError('Special permission bits on a config are unsupported. Ask the administrator to review the file.')
        parent_mode = stat.S_IMODE(self.path.parent.stat().st_mode)
        if not mode & 0o222 or not parent_mode & 0o222:
            raise ConfigError('Read-only file/directory: no write attempted. Do not bypass production permissions.')
        lock = self.path.with_name(self.path.name + '.connector-manager.lock')
        windows_security = WindowsSecurity() if os.name == 'nt' else None
        source_security = windows_security.read(self.path) if windows_security else None
        lock_fd = None
        backup = stage = None
        replaced = False
        try:
            try:
                lock_fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            except FileExistsError:
                raise ConfigError('Another session (or a stale lock) exists. Do not remove its lock until its owner is known to be stopped.') from None
            os.write(lock_fd, f'pid={os.getpid()}\n'.encode('ascii'))
            os.fsync(lock_fd)
            self.check_current()
            stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
            backup = self.path.with_name(self.path.name + '.' + stamp + '.' + uuid.uuid4().hex + '.bak')
            self._exclusive_write(backup, self.document.data, source_security)
            _, backup_data, _ = safe_read(backup)
            if digest(backup_data) != self.document.sha256:
                raise ConfigError('Backup verification failed. Original was not overwritten.')
            self._sync_directory()
            stage = self.path.with_name('.' + self.path.name + '.' + uuid.uuid4().hex + '.staging')
            self._exclusive_write(stage, data, source_security)
            _, staged, _ = safe_read(stage)
            Document(staged, self.path)
            if digest(staged) != plan['result_sha256']:
                raise ConfigError('Staging verification failed. Original was not overwritten.')
            self._check_security_metadata(stage)
            self._preserve_owner(stage)
            self.check_current()
            if windows_security:
                if windows_security.read(self.path)[1] != source_security[1]:
                    raise ConfigError('Source Windows security changed since opening the transaction. Original not overwritten.')
                windows_security.apply(stage, source_security)
            os.replace(stage, self.path)
            replaced = True
            stage = None
            # Keep staging owner-only; restore the original POSIX mode only after replacement.
            guarded_path(self.path)
            if os.chmod in os.supports_follow_symlinks:
                os.chmod(self.path, mode, follow_symlinks=False)
            else:
                os.chmod(self.path, mode)
            self._sync_directory()
            if windows_security and windows_security.read(self.path)[1] != source_security[1]:
                raise ConfigError('Replacement occurred but Windows security verification failed. Inspect the current file and backup; no automatic rollback was attempted.')
            _, final, _ = safe_read(self.path)
            if digest(final) != digest(data):
                raise ConfigError('Apply completed but a concurrent writer changed the result. Backup retained; do NOT roll it back blindly.')
            return {'updated': str(self.path), 'backup': str(backup), 'changes': len(rows),
                    'backup_sha256': self.document.sha256, 'result_sha256': digest(final)}
        except ConfigError:
            raise
        except (OSError, NotImplementedError):
            if replaced:
                raise ConfigError('Replacement occurred, but final permission/durability verification failed. Inspect the current file and timestamped backup before any further edits. No automatic rollback was attempted.') from None
            raise ConfigError('Write failed safely before replacement. Original not overwritten; any completed timestamped backup is retained. Check directory permissions, free space and file locks.') from None
        finally:
            if stage is not None:
                try:
                    stage.unlink()
                except OSError:
                    pass
            if lock_fd is not None:
                os.close(lock_fd)
                try:
                    lock.unlink()
                except OSError:
                    pass

    @staticmethod
    def _check_security_metadata(path):
        if os.name != 'nt' and hasattr(os, 'listxattr'):
            try:
                attributes = os.listxattr(path, follow_symlinks=False)
            except OSError:
                raise ConfigError('Cannot inspect extended file security metadata. Apply is refused; use an administrator-approved local filesystem.') from None
            if attributes:
                raise ConfigError('File has extended attributes / POSIX ACLs that this tool cannot preserve reliably. Apply is refused; use your approved administrative editor.')

    def _preserve_owner(self, stage):
        if os.name != 'nt':
            fd = os.open(stage, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                st = os.fstat(fd)
                if (st.st_uid, st.st_gid) != (self.stat.st_uid, self.stat.st_gid):
                    os.fchown(fd, self.stat.st_uid, self.stat.st_gid)
                    st = os.fstat(fd)
                if (st.st_uid, st.st_gid) != (self.stat.st_uid, self.stat.st_gid):
                    raise ConfigError('Cannot preserve original file owner/group. Apply refused before replacement.')
                os.fsync(fd)
            finally:
                os.close(fd)

    @staticmethod
    def _require_private(fd):
        if os.name != 'nt' and stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
            raise ConfigError('This filesystem cannot enforce owner-only staging/backup permissions. Use a secured local filesystem; no configuration payload was written.')

    @staticmethod
    def _exclusive_write(path, data, source_security=None):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as f:
            if os.name == 'nt' and source_security is not None:
                WindowsSecurity().apply(path, source_security)
            Session._require_private(f.fileno())
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def _sync_directory(self):
        if os.name != 'nt':
            fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def write_plan(path, plan):
    p = Path(path).expanduser()
    payload = (json.dumps(plan, indent=2) + '\n').encode('utf-8')
    try:
        Session._exclusive_write(p, payload)
    except FileExistsError:
        raise ConfigError('Plan destination already exists. Choose a new plan filename.') from None
    except OSError:
        raise ConfigError('Cannot create the plan file.') from None


def read_plan(path):
    try:
        plan = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(plan, dict):
            raise ValueError()
        return plan
    except (OSError, ValueError):
        raise ConfigError('Cannot read a valid JSON plan.') from None


def cli(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    listing = commands.add_parser('list', help='Read-only inventory (no credentials or endpoints).')
    listing.add_argument('config')
    listing.add_argument('--vendor', default='')
    listing.add_argument('--transport', default='')
    listing.add_argument('--status', choices=('all', 'enabled', 'disabled'), default='all')
    listing.add_argument('--search', default='')
    planning = commands.add_parser('plan', help='Validate and save a secret-free change plan; no config writes.')
    planning.add_argument('config')
    planning.add_argument('--enable', action='append', default=[], metavar='KEY')
    planning.add_argument('--disable', action='append', default=[], metavar='KEY')
    planning.add_argument('--environment', choices=ENVIRONMENTS, default='unknown')
    planning.add_argument('--ack-production', action='store_true')
    planning.add_argument('--out', required=True, help='New JSON plan destination; existing files are never overwritten.')
    applying = commands.add_parser('apply', help='Explicitly apply a previously reviewed plan.')
    applying.add_argument('config')
    applying.add_argument('--plan', required=True)
    applying.add_argument('--apply', action='store_true', help='Required explicit write confirmation.')
    applying.add_argument('--writers-coordinated', action='store_true', help='Confirm all services/editors/deployment writers are stopped or coordinated.')
    applying.add_argument('--ack-production', action='store_true', help='Fresh acknowledgement required again for production writes.')
    args = parser.parse_args(argv)
    session = Session(args.config)
    for warning in session.document.warnings:
        print('WARNING: ' + warning, file=sys.stderr)
    if args.command == 'list':
        rows = session.document.connectors
        for c in rows:
            status = 'enabled' if c.enabled else 'disabled'
            searchable = ' '.join(str(v) for v in c.public().values()).casefold()
            if args.vendor.casefold() not in c.vendor.casefold() or args.transport.casefold() not in c.transport.casefold():
                continue
            if args.status not in ('all', status) or args.search.casefold() not in searchable:
                continue
            print(f'{c.key}\t{status}\t{c.vendor}\t{c.transport}\t{c.direction}\t{c.identifier}' + ('\t[manual edit only]' if not c.supported else ''))
        print(f'Total: {len(rows)} definitions; enabled={sum(c.enabled for c in rows)}, disabled={sum(not c.enabled for c in rows)}', file=sys.stderr)
    elif args.command == 'plan':
        if set(args.enable) & set(args.disable):
            raise ConfigError('The same definition cannot be enabled and disabled in one plan.')
        changes = {key: True for key in args.enable}
        changes.update({key: False for key in args.disable})
        plan = session.plan(changes, args.environment, args.ack_production)
        write_plan(args.out, plan)
        print(json.dumps(plan['preview'], indent=2))
        print('Plan saved. Review it before running the separate apply command.')
    else:
        if not args.apply:
            raise ConfigError('No write attempted. Review the plan and add --apply explicitly.')
        plan = read_plan(args.plan)
        if (session.document.production or plan.get('environment') == 'prod') and not args.ack_production:
            raise ConfigError('Apply requires a fresh --ack-production acknowledgement.')
        result = session.apply(plan, writers_coordinated=args.writers_coordinated)
        print(json.dumps(result, indent=2))
    return 0


def gui():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
        root = tk.Tk()
    except Exception:
        print('GUI unavailable (Tkinter/display required). Use: python connector_manager.py --help', file=sys.stderr)
        return 2
    root.title('Local Connector Manager — preview before applying')
    root.geometry('1220x800')
    session, staged, reviewed = None, {}, None
    path = tk.StringVar()
    environment = tk.StringVar(value='unknown')
    production_ack = tk.BooleanVar(value=False)
    writers_ack = tk.BooleanVar(value=False)
    vendor, transport, status, search = (tk.StringVar(value='All') for _ in range(4))
    search.set('')
    banner = tk.StringVar(value='Open a customer config. Enabled means an uncommented definition, NOT runtime health.')
    top = ttk.Frame(root, padding=10)
    top.pack(fill='x')
    ttk.Label(top, text='Configuration path').pack(side='left')
    ttk.Entry(top, textvariable=path, width=95).pack(side='left', fill='x', expand=True, padx=8)

    def invalidate(*_):
        nonlocal reviewed
        reviewed = None
        apply_button.state(['disabled'])

    def target_matches():
        return session is not None and Path(os.path.abspath(os.path.expanduser(path.get()))) == session.path

    path.trace_add('write', invalidate)

    def refresh(*_):
        invalidate()
        tree.delete(*tree.get_children())
        if session is None:
            return
        for c in session.document.connectors:
            current = 'Enabled' if c.enabled else 'Disabled'
            if vendor.get() not in ('All', c.vendor) or transport.get() not in ('All', c.transport) or status.get() not in ('All', current):
                continue
            if search.get().casefold() not in ' '.join(str(v) for v in c.public().values()).casefold():
                continue
            pending = ('Enable' if staged[c.key] else 'Disable') if c.key in staged else ''
            tree.insert('', 'end', iid=c.key, values=(current, c.vendor, c.transport, c.direction, c.identifier,
                                                     c.key, pending, 'Yes' if c.supported else 'Manual only'))
        counts = Counter('Enabled' if c.enabled else 'Disabled' for c in session.document.connectors)
        banner.set(f'{counts["Enabled"]} enabled / {counts["Disabled"]} disabled • {len(staged)} staged. No service restart/reload is performed.')

    def load():
        nonlocal session
        if staged and not messagebox.askyesno('Discard staged changes?', 'Reloading discards the current staged plan. Continue?'):
            return
        try:
            candidate = Session(path.get())
        except ConfigError as exc:
            messagebox.showerror('Open failed', str(exc))
            return
        session = candidate
        staged.clear()
        production_ack.set(False)
        writers_ack.set(False)
        environment.set('unknown')
        vendor_combo['values'] = ['All'] + sorted({c.vendor for c in session.document.connectors})
        transport_combo['values'] = ['All'] + sorted({c.transport for c in session.document.connectors})
        vendor.set('All'); transport.set('All'); status.set('All'); search.set('')
        warning_box.configure(state='normal')
        warning_box.delete('1.0', 'end')
        warning_box.insert('end', '\n'.join(session.document.warnings) or 'No production markers detected. Select the correct environment explicitly.')
        warning_box.configure(state='disabled')
        preview_box.configure(state='normal'); preview_box.delete('1.0', 'end'); preview_box.configure(state='disabled')
        refresh()

    def browse():
        selected = filedialog.askopenfilename(filetypes=[('Config / XML', '*.config *.xml'), ('All files', '*.*')])
        if selected:
            path.set(selected)
            load()

    ttk.Button(top, text='Browse…', command=browse).pack(side='left')
    ttk.Button(top, text='Open / Reload', command=load).pack(side='left', padx=6)
    filters = ttk.Frame(root, padding=(10, 0, 10, 8))
    filters.pack(fill='x')
    for label, var, values, width in [('Vendor', vendor, ['All'], 17), ('Transport', transport, ['All'], 15),
                                      ('Status', status, ['All', 'Enabled', 'Disabled'], 12)]:
        ttk.Label(filters, text=label).pack(side='left', padx=(0, 4))
        combo = ttk.Combobox(filters, textvariable=var, values=values, state='readonly', width=width)
        combo.pack(side='left', padx=(0, 14))
        if label == 'Vendor': vendor_combo = combo
        if label == 'Transport': transport_combo = combo
        var.trace_add('write', refresh)
    ttk.Label(filters, text='Search').pack(side='left')
    ttk.Entry(filters, textvariable=search).pack(side='left', fill='x', expand=True, padx=6)
    search.trace_add('write', refresh)
    table_frame = ttk.Frame(root, padding=(10, 0))
    table_frame.pack(fill='both', expand=True)
    columns = ('Status', 'Vendor', 'Transport', 'Direction', 'Identifier', 'Definition key', 'Staged', 'Editable')
    tree = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='extended')
    for col, width in zip(columns, (75, 110, 100, 80, 210, 185, 75, 85)):
        tree.heading(col, text=col)
        tree.column(col, width=width, minwidth=65)
    scroll = ttk.Scrollbar(table_frame, orient='vertical', command=tree.yview)
    horizontal = ttk.Scrollbar(table_frame, orient='horizontal', command=tree.xview)
    tree.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
    scroll.pack(side='right', fill='y'); horizontal.pack(side='bottom', fill='x'); tree.pack(fill='both', expand=True)

    def stage(enabled):
        if session is None:
            return
        for key in tree.selection():
            if session.document.by_key[key].enabled == enabled:
                staged.pop(key, None)
            else:
                staged[key] = enabled
        refresh()

    def clear():
        staged.clear()
        refresh()

    controls = ttk.Frame(root, padding=10)
    controls.pack(fill='x')
    ttk.Button(controls, text='Stage Enable selected', command=lambda: stage(True)).pack(side='left')
    ttk.Button(controls, text='Stage Disable selected', command=lambda: stage(False)).pack(side='left', padx=6)
    ttk.Button(controls, text='Clear plan', command=clear).pack(side='left')
    ttk.Label(controls, text='Environment').pack(side='left', padx=(20, 5))
    ttk.Combobox(controls, textvariable=environment, values=ENVIRONMENTS, state='readonly', width=9).pack(side='left')
    ttk.Checkbutton(controls, text='I acknowledge production risk', variable=production_ack).pack(side='left', padx=10)
    environment.trace_add('write', invalidate)
    production_ack.trace_add('write', invalidate)
    ttk.Checkbutton(root, text='I confirm services, editors and deployment/config writers are stopped or coordinated', variable=writers_ack).pack(anchor='w', padx=10)
    writers_ack.trace_add('write', invalidate)
    warning_box = tk.Text(root, height=3, wrap='word', padx=10, foreground='#8a3000', state='disabled')
    warning_box.pack(fill='x', padx=10)
    preview_box = tk.Text(root, height=8, wrap='word', padx=10, state='disabled')
    preview_box.pack(fill='x', padx=10, pady=6)

    def preview():
        nonlocal reviewed
        if session is None:
            return
        try:
            if not target_matches():
                raise ConfigError('Displayed path differs from the opened file. Open / Reload the intended file before previewing.')
            session.check_current()
            reviewed = session.plan(staged, environment.get(), production_ack.get())
            lines = [f'{r["key"]} | {r["identifier"]} | {r["transport"]} {r["direction"]}: {r["from"]} → {r["to"]}' for r in reviewed['preview']]
            preview_box.configure(state='normal'); preview_box.delete('1.0', 'end')
            preview_box.insert('end', 'TARGET: ' + str(session.path) + '\n' + '\n'.join(lines) + '\n\nApply creates a verified timestamped backup next to the original, then replaces the original file.')
            preview_box.configure(state='disabled')
            apply_button.state(['!disabled'])
        except ConfigError as exc:
            invalidate()
            messagebox.showerror('Plan needs attention', str(exc))

    def apply():
        if reviewed is None:
            return
        if not target_matches():
            invalidate()
            messagebox.showerror('Reload required', 'Displayed path differs from the opened file. Open / Reload and review again.')
            return
        if not messagebox.askyesno('Apply reviewed changes?', f'Overwrite this exact configuration?\n{session.path}\n\n{len(reviewed["changes"])} reviewed change(s).\nA verified original backup will be created next to it.\nNo restart/reload/deploy is performed.'):
            return
        try:
            result = session.apply(reviewed, writers_coordinated=writers_ack.get())
            messagebox.showinfo('Applied', 'Updated: ' + result['updated'] + '\nBackup: ' + result['backup'])
            staged.clear()
            load()
        except ConfigError as exc:
            invalidate()
            messagebox.showerror('Apply stopped — inspect before retry', str(exc))

    bottom = ttk.Frame(root, padding=10)
    bottom.pack(fill='x')
    ttk.Button(bottom, text='Preview staged changes', command=preview).pack(side='left')
    apply_button = ttk.Button(bottom, text='Apply reviewed plan…', command=apply, state='disabled')
    apply_button.pack(side='left', padx=10)
    ttk.Label(root, textvariable=banner, padding=8).pack(fill='x')
    def close():
        if not staged or messagebox.askyesno('Close without applying?', 'Discard the staged plan and close?'):
            root.destroy()
    root.protocol('WM_DELETE_WINDOW', close)
    root.mainloop()
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        return cli(argv) if argv else gui()
    except ConfigError as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        print('ERROR: Operation could not be completed safely. Check file access and plan structure. Source details are withheld.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
