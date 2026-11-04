"""Secret-free tests. Test scratch files stay under this project and are removed."""
import codecs
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import unittest
from unittest import mock
import uuid

import connector_manager as cm

HERE = Path(__file__).resolve().parent
SAMPLE = (HERE / 'sample.Customer.config').read_bytes()


def element(identifier='GammaIn', kind='Inbound', type_name='BatchFileSystemInConnector', props='', body=''):
    return f'<LocalConnector identifier="{identifier}" kind="{kind}" type="Example.{type_name}, Example"><Properties>{props}</Properties>{body}</LocalConnector>'


def document(content):
    return ('<configuration><IntegrationServiceCustomerConfigurationSection><LocalConnectors>' + content +
            '</LocalConnectors></IntegrationServiceCustomerConfigurationSection></configuration>').encode()


@contextmanager
def scratch():
    directory = HERE / ('.test-work-' + uuid.uuid4().hex)
    directory.mkdir(mode=0o700)
    try:
        yield directory
    finally:
        shutil.rmtree(directory)


def private_modes_supported():
    with scratch() as directory:
        path = directory / 'capability-probe'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            return not stat.S_IMODE(os.fstat(fd).st_mode) & 0o077
        finally:
            os.close(fd)


PRIVATE_MODES = private_modes_supported()


class InventoryTests(unittest.TestCase):
    def test_sample_counts_and_unique_definition_keys(self):
        doc = cm.Document(SAMPLE)
        self.assertEqual(len(doc.connectors), 3)
        self.assertEqual(sum(c.enabled for c in doc.connectors), 1)
        self.assertEqual(len(doc.by_key), 3)
        self.assertEqual(len({c.key for c in doc.connectors if c.identifier == 'AcmeIn'}), 2)

    def test_xml_attribute_quoting_cdata_and_fake_markup(self):
        raw = element(props='<Property name="Description" value="A &gt; B" />', body='<![CDATA[<LocalConnector/>]]>')
        doc = cm.Document(document(raw))
        self.assertEqual(len(doc.connectors), 1)
        changed, _ = doc.preview({doc.connectors[0].key: False}, 'test')
        self.assertEqual(len(cm.Document(changed).connectors), 1)

    def test_transport_uses_usesftp_not_disablesftp4(self):
        for value, expected in [('true', 'SFTP'), ('false', 'FTP'), ('', 'FTP/Unknown')]:
            with self.subTest(value=value):
                props = '<Property name="DisableSftp4" value="true" />'
                if value:
                    props += f'<Property name="UseSftp" value="{value}" />'
                doc = cm.Document(document(element(type_name='FtpInConnector', props=props)))
                self.assertEqual(doc.connectors[0].transport, expected)

    def test_unsupported_comment_warns_and_is_untouched(self):
        raw = document(element() + '<!-- prose <LocalConnector broken -->')
        doc = cm.Document(raw)
        self.assertEqual(len(doc.connectors), 1)
        self.assertTrue(any('Unsupported' in w for w in doc.warnings))
        changed, _ = doc.preview({doc.connectors[0].key: False}, 'test')
        self.assertIn(b'<!-- prose <LocalConnector broken -->', changed)

    def test_nested_commented_definition_is_not_guessed(self):
        doc = cm.Document(document('<!--<Container>' + element() + '</Container>-->'))
        self.assertEqual(len(doc.connectors), 0)
        self.assertTrue(doc.warnings)

    def test_parseable_prose_does_not_become_definition(self):
        doc = cm.Document(document('<!-- LocalConnector: this is just prose. -->'))
        self.assertEqual(doc.connectors, [])

    def test_internal_comments_refuse_disable(self):
        doc = cm.Document(document(element(body='<!-- keep me -->')))
        self.assertFalse(doc.connectors[0].supported)
        with self.assertRaisesRegex(cm.ConfigError, 'internal comments'):
            doc.preview({doc.connectors[0].key: False}, 'test')

    def test_literal_double_hyphen_refuse_disable(self):
        doc = cm.Document(document(element(props='<Property name="Note" value="a--b" />')))
        with self.assertRaises(cm.ConfigError):
            doc.preview({doc.connectors[0].key: False}, 'test')

    def test_dtd_refused(self):
        with self.assertRaisesRegex(cm.ConfigError, 'DTD'):
            cm.Document(b'<!DOCTYPE configuration [<!ENTITY x "hidden">]>' + document(element()))

    def test_duplicate_active_identifier_refused(self):
        with self.assertRaisesRegex(cm.ConfigError, 'Duplicate active'):
            cm.Document(document(element() + element(identifier='gammain')))

    def test_missing_identifier_refused(self):
        with self.assertRaises(cm.ConfigError):
            cm.Document(document('<LocalConnector/>'))

    def test_wrong_section_refused(self):
        with self.assertRaises(cm.ConfigError):
            cm.Document(b'<configuration/>')

    def test_malformed_xml_does_not_leak_content(self):
        with self.assertRaises(cm.ConfigError) as result:
            cm.Document(b'<secret sentinel-secret="never-log">')
        self.assertNotIn('sentinel-secret', str(result.exception))

    def test_public_inventory_omits_all_properties(self):
        doc = cm.Document(document(element(props='<Property name="Password" value="sentinel-secret" />')))
        self.assertNotIn('sentinel-secret', json.dumps(doc.connectors[0].public()))


class PreviewTests(unittest.TestCase):
    def test_multi_comment_enable_only_one_preserves_prose(self):
        doc = cm.Document(SAMPLE)
        beta = next(c for c in doc.connectors if c.identifier == 'BetaOut')
        result, rows = doc.preview({beta.key: True}, 'test')
        updated = cm.Document(result)
        self.assertEqual(sum(c.enabled for c in updated.connectors), 2)
        self.assertFalse(next(c for c in updated.connectors if c.transport == 'SFTP').enabled)
        self.assertIn(b'Alternative definition: explicitly disable the active AcmeIn', result)
        self.assertEqual(len(rows), 1)

    def test_alternative_requires_explicit_counterpart_disable(self):
        doc = cm.Document(SAMPLE)
        alt = next(c for c in doc.connectors if c.transport == 'SFTP')
        with self.assertRaisesRegex(cm.ConfigError, 'Explicitly stage Disable'):
            doc.preview({alt.key: True}, 'test')
        active = next(c for c in doc.connectors if c.enabled)
        result, rows = doc.preview({alt.key: True, active.key: False}, 'test')
        self.assertEqual(len(rows), 2)
        self.assertEqual([c.transport for c in cm.Document(result).connectors if c.enabled], ['SFTP'])

    def test_multiple_enable_in_one_comment(self):
        doc = cm.Document(document('<!-- before ' + element(identifier='AIn') + ' between ' + element(identifier='BOut') + ' after -->'))
        result, _ = doc.preview({c.key: True for c in doc.connectors}, 'test')
        self.assertEqual(sum(c.enabled for c in cm.Document(result).connectors), 2)
        for prose in (b' before ', b' between ', b' after '):
            self.assertIn(prose, result)

    def test_unknown_environment_refused(self):
        doc = cm.Document(SAMPLE)
        with self.assertRaisesRegex(cm.ConfigError, 'Choose'):
            doc.preview({doc.connectors[0].key: False}, 'unknown')

    def test_production_marker_requires_ack_even_in_test(self):
        doc = cm.Document(SAMPLE, 'C:/SWIBP1/Customer.config')
        with self.assertRaisesRegex(cm.ConfigError, 'acknowledgement'):
            doc.preview({doc.connectors[0].key: False}, 'test')
        doc.preview({doc.connectors[0].key: False}, 'test', True)

    def test_prod_environment_requires_ack_without_marker(self):
        doc = cm.Document(SAMPLE)
        with self.assertRaises(cm.ConfigError):
            doc.preview({doc.connectors[0].key: False}, 'prod')

    def test_ice_outbound_blocked_nonprod_even_with_ack(self):
        for identifier in ('ICEOut', 'ICE360Outbound'):
            doc = cm.Document(document('<!--' + element(identifier, 'Outbound', 'FtpOutConnector') + '-->'))
            with self.assertRaisesRegex(cm.ConfigError, 'PROD only'):
                doc.preview({doc.connectors[0].key: True}, 'uat', True)
            doc.preview({doc.connectors[0].key: True}, 'prod', True)

    def test_noop_and_unknown_keys_refused(self):
        doc = cm.Document(SAMPLE)
        for changes in ({}, {'missing': True}, {doc.connectors[0].key: True}):
            with self.assertRaises(cm.ConfigError):
                doc.preview(changes, 'test')

    def test_bom_crlf_and_unrelated_bytes_preserved(self):
        source = codecs.BOM_UTF8 + SAMPLE.replace(b'\n', b'\r\n')
        doc = cm.Document(source)
        active = next(c for c in doc.connectors if c.enabled)
        result, _ = doc.preview({active.key: False}, 'test')
        original_text = doc.text[active.start:active.end].encode('utf-8')
        expected = source.replace(original_text, b'<!--' + original_text + b'-->', 1)
        self.assertEqual(result, expected)
        self.assertEqual(result.count(b'\r\n'), source.count(b'\r\n'))

    def test_utf16_le_and_be_roundtrip(self):
        for encoding, bom in (('utf-16-le', codecs.BOM_UTF16_LE), ('utf-16-be', codecs.BOM_UTF16_BE)):
            source = bom + SAMPLE.decode().replace('utf-8', 'utf-16').encode(encoding)
            doc = cm.Document(source)
            self.assertEqual(doc.encode(doc.text), source)
            result, _ = doc.preview({doc.connectors[0].key: False}, 'test')
            self.assertTrue(result.startswith(bom))
            self.assertEqual(sum(c.enabled for c in cm.Document(result).connectors), 0)

    def test_windows_1252_roundtrip(self):
        source = SAMPLE.decode().replace('utf-8', 'windows-1252').replace('Synthetic fixture', 'Synthetic café fixture').encode('cp1252')
        doc = cm.Document(source)
        result, _ = doc.preview({doc.connectors[0].key: False}, 'test')
        self.assertIn(b'caf\xe9', result)

    def test_keys_stable_for_same_snapshot(self):
        self.assertEqual(list(cm.Document(SAMPLE).by_key), list(cm.Document(SAMPLE).by_key))


class TransactionTests(unittest.TestCase):
    def setUp(self):
        if os.name != 'nt' and not PRIVATE_MODES:
            # Some mounted test workspaces ignore mode bits. Only synthetic payloads are used.
            self.private_patch = mock.patch.object(cm.Session, '_require_private')
            self.private_patch.start()
            self.addCleanup(self.private_patch.stop)
            metadata_patch = mock.patch.object(cm.Session, '_check_security_metadata')
            metadata_patch.start()
            self.addCleanup(metadata_patch.stop)

    def setup_session(self, directory):
        path = directory / 'Customer.config'
        path.write_bytes(SAMPLE)
        if not PRIVATE_MODES:
            time.sleep(0.03)
        session = cm.Session(path)
        plan = session.plan({session.document.connectors[0].key: False}, 'test')
        return path, session, plan

    def test_apply_backup_exact_mode_and_cleanup(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            result = session.apply(plan, writers_coordinated=True)
            self.assertEqual(Path(result['backup']).read_bytes(), SAMPLE)
            self.assertEqual(sum(c.enabled for c in cm.Document(path.read_bytes()).connectors), 0)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), stat.S_IMODE(session.stat.st_mode))
            if os.name != 'nt' and PRIVATE_MODES:
                self.assertEqual(stat.S_IMODE(Path(result['backup']).stat().st_mode), 0o600)
            self.assertFalse(list(d.glob('*.lock')))
            self.assertFalse(list(d.glob('*.staging')))

    def test_stale_file_rejected_without_backup(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            changed = SAMPLE + b'\n'
            path.write_bytes(changed)
            with self.assertRaisesRegex(cm.ConfigError, 'STALE'):
                session.apply(plan, writers_coordinated=True)
            self.assertEqual(path.read_bytes(), changed)
            self.assertFalse(list(d.glob('*.bak')))

    def test_final_stale_recheck_retains_backup_no_overwrite(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            original_write = session._exclusive_write
            def injecting_write(destination, payload, security=None):
                original_write(destination, payload, security)
                if str(destination).endswith('.staging'):
                    path.write_bytes(SAMPLE + b'\n')
            with mock.patch.object(session, '_exclusive_write', side_effect=injecting_write):
                with self.assertRaisesRegex(cm.ConfigError, 'STALE'):
                    session.apply(plan, writers_coordinated=True)
            self.assertEqual(path.read_bytes(), SAMPLE + b'\n')
            self.assertEqual(len(list(d.glob('*.bak'))), 1)
            self.assertFalse(list(d.glob('*.staging')))

    def test_backup_failure_no_replace(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            with mock.patch.object(session, '_exclusive_write', side_effect=PermissionError()):
                with self.assertRaises(cm.ConfigError):
                    session.apply(plan, writers_coordinated=True)
            self.assertEqual(path.read_bytes(), SAMPLE)

    def test_replace_failure_no_original_damage(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            with mock.patch.object(cm.os, 'replace', side_effect=PermissionError()):
                with self.assertRaises(cm.ConfigError):
                    session.apply(plan, writers_coordinated=True)
            self.assertEqual(path.read_bytes(), SAMPLE)
            self.assertEqual(len(list(d.glob('*.bak'))), 1)
            self.assertFalse(list(d.glob('*.staging')))

    def test_existing_lock_is_never_removed(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            lock = path.with_name(path.name + '.connector-manager.lock')
            lock.write_text('other owner')
            with self.assertRaisesRegex(cm.ConfigError, 'lock'):
                session.apply(plan, writers_coordinated=True)
            self.assertEqual(lock.read_text(), 'other owner')
            self.assertEqual(path.read_bytes(), SAMPLE)

    def test_readonly_source_refused(self):
        if os.name != 'nt' and not PRIVATE_MODES:
            self.skipTest('Mounted workspace does not implement chmod; synthetic permission-branch test covers refusal.')
        with scratch() as d:
            path, session, _ = self.setup_session(d)
            path.chmod(0o400)
            try:
                session = cm.Session(path)
                plan = session.plan({session.document.connectors[0].key: False}, 'test')
                with self.assertRaisesRegex(cm.ConfigError, 'Read-only'):
                    session.apply(plan, writers_coordinated=True)
                self.assertEqual(path.read_bytes(), SAMPLE)
            finally:
                path.chmod(0o600)

    def test_symlink_source_refused(self):
        if os.name == 'nt':
            self.skipTest('Symlink creation often requires Windows privileges.')
        with scratch() as d:
            path, _, _ = self.setup_session(d)
            link = d / 'link.config'
            try:
                link.symlink_to(path)
            except OSError:
                self.skipTest('Mounted workspace does not support creating symlinks.')
            with self.assertRaisesRegex(cm.ConfigError, 'Symlinks'):
                cm.Session(link)

    def test_replaced_source_inode_refused(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            other = d / 'other.config'
            other.write_bytes(SAMPLE)
            os.replace(other, path)
            with self.assertRaisesRegex(cm.ConfigError, 'STALE'):
                session.apply(plan, writers_coordinated=True)

    def test_modified_plan_preview_rejected(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            plan['preview'][0]['to'] = 'enabled'
            with self.assertRaisesRegex(cm.ConfigError, 'preview'):
                session.apply(plan, writers_coordinated=True)
            self.assertEqual(path.read_bytes(), SAMPLE)

    def test_plan_file_exclusive_and_secret_free(self):
        with scratch() as d:
            _, _, plan = self.setup_session(d)
            path = d / 'plan.json'
            cm.write_plan(path, plan)
            self.assertEqual(cm.read_plan(path), plan)
            self.assertNotIn('<LocalConnector', path.read_text())
            with self.assertRaises(cm.ConfigError):
                cm.write_plan(path, plan)

    def test_final_permission_failure_reports_already_replaced(self):
        with scratch() as d:
            path, session, plan = self.setup_session(d)
            with mock.patch.object(cm.os, 'chmod', side_effect=PermissionError()):
                with self.assertRaisesRegex(cm.ConfigError, 'Replacement occurred'):
                    session.apply(plan, writers_coordinated=True)
            self.assertNotEqual(path.read_bytes(), SAMPLE)
            self.assertEqual(len(list(d.glob('*.bak'))), 1)


class SecurityCapabilityTests(unittest.TestCase):
    def test_private_mode_refusal_happens_before_payload_write(self):
        if os.name == 'nt' or PRIVATE_MODES:
            self.skipTest('This platform enforces private modes or uses Windows ACLs.')
        with scratch() as d:
            path = d / 'refused.backup'
            with self.assertRaisesRegex(cm.ConfigError, 'owner-only'):
                cm.Session._exclusive_write(path, b'synthetic-only-payload')
            self.assertEqual(path.read_bytes(), b'')

    def test_private_mode_check_rejects_group_world_permissions(self):
        if os.name == 'nt':
            self.skipTest('Windows uses inherited ACL checks, not POSIX modes.')
        with mock.patch.object(cm.os, 'fstat', return_value=mock.Mock(st_mode=0o100644)):
            with self.assertRaisesRegex(cm.ConfigError, 'owner-only'):
                cm.Session._require_private(123)

    def test_posix_acl_refusal(self):
        if os.name == 'nt' or not hasattr(os, 'listxattr'):
            self.skipTest('POSIX xattrs unavailable.')
        with mock.patch.object(cm.os, 'listxattr', return_value=['system.posix_acl_access']):
            with self.assertRaisesRegex(cm.ConfigError, 'ACLs'):
                cm.Session._check_security_metadata(HERE)

    def test_uninspectable_security_metadata_refused(self):
        if os.name == 'nt' or not hasattr(os, 'listxattr'):
            self.skipTest('POSIX xattrs unavailable.')
        with mock.patch.object(cm.os, 'listxattr', side_effect=OSError()):
            with self.assertRaisesRegex(cm.ConfigError, 'inspect'):
                cm.Session._check_security_metadata(HERE)

    def test_readonly_permission_branch_without_chmod_dependency(self):
        with scratch() as d:
            path = d / 'Customer.config'; path.write_bytes(SAMPLE)
            session = cm.Session(path)
            plan = session.plan({session.document.connectors[0].key: False}, 'test')
            session.stat = os.stat_result((stat.S_IFREG | 0o400, *tuple(session.stat)[1:]))
            with mock.patch.object(session, 'check_current'), mock.patch.object(session, '_check_security_metadata'):
                with self.assertRaisesRegex(cm.ConfigError, 'Read-only'):
                    session.apply(plan, writers_coordinated=True)
            self.assertEqual(path.read_bytes(), SAMPLE)

    def test_reparse_or_symlink_branch_without_symlink_privilege(self):
        original = Path.lstat
        def injected(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return os.stat_result((stat.S_IFLNK | 0o777, *tuple(info)[1:]))
        with mock.patch.object(Path, 'lstat', injected):
            with self.assertRaisesRegex(cm.ConfigError, 'Symlinks'):
                cm.guarded_path(HERE / 'sample.Customer.config')


class WindowsSecurityLogicTests(unittest.TestCase):
    def api_stub(self, actual=None):
        import ctypes
        security = cm.WindowsSecurity.__new__(cm.WindowsSecurity)
        security.c = ctypes
        security.api = mock.Mock()
        security.api.SetFileSecurityW.return_value = 1
        signature = (b'synthetic-owner', b'synthetic-group', b'synthetic-dacl', True)
        security.read = mock.Mock(return_value=(b'descriptor', actual or signature))
        return security, (b'synthetic-descriptor', signature)

    def test_native_copy_requires_post_set_security_verification(self):
        security, source = self.api_stub()
        security.apply('synthetic-path', source)
        security.read.assert_called_once_with('synthetic-path')
        self.assertEqual(security.api.SetFileSecurityW.call_args.args[1], 7 | 0x80000000)

    def test_native_copy_signature_mismatch_fails_closed(self):
        security, source = self.api_stub(actual=(b'wrong-owner', b'g', b'acl', True))
        with self.assertRaisesRegex(cm.ConfigError, 'verification failed'):
            security.apply('synthetic-path', source)

    def test_native_set_security_failure_fails_closed(self):
        security, source = self.api_stub()
        security.api.SetFileSecurityW.return_value = 0
        with self.assertRaises(cm.ConfigError):
            security.apply('synthetic-path', source)

    @unittest.skipUnless(os.name == 'nt', 'Native Windows security APIs require Windows.')
    def test_real_windows_security_copy_on_synthetic_file(self):
        with scratch() as d:
            source = d / 'source.config'; source.write_bytes(SAMPLE)
            security = cm.WindowsSecurity()
            descriptor = security.read(source)
            target = d / 'backup.config'
            cm.Session._exclusive_write(target, SAMPLE, descriptor)
            self.assertEqual(target.read_bytes(), SAMPLE)
            self.assertEqual(security.read(target)[1], descriptor[1])


class CliTests(unittest.TestCase):
    def setUp(self):
        if os.name != 'nt' and not PRIVATE_MODES:
            self.private_patch = mock.patch.object(cm.Session, '_require_private')
            self.private_patch.start()
            self.addCleanup(self.private_patch.stop)
            metadata_patch = mock.patch.object(cm.Session, '_check_security_metadata')
            metadata_patch.start()
            self.addCleanup(metadata_patch.stop)

    def run_cli(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                code = cm.main(list(map(str, args)))
            except SystemExit as exc:
                code = exc.code
        return subprocess.CompletedProcess(args, code, output.getvalue(), errors.getvalue())

    def test_real_subprocess_help(self):
        result = subprocess.run([sys.executable, str(HERE / 'connector_manager.py'), '--help'],
                                capture_output=True, text=True, cwd=HERE)
        self.assertEqual(result.returncode, 0)
        self.assertIn('list', result.stdout)

    def test_help(self):
        result = self.run_cli('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('plan', result.stdout)

    def test_list_is_readonly_and_filters(self):
        with scratch() as d:
            path = d / 'Customer.config'; path.write_bytes(SAMPLE)
            result = self.run_cli('list', path, '--transport', 'SFTP', '--status', 'disabled')
            self.assertEqual(result.returncode, 0)
            self.assertIn('SFTP', result.stdout)
            self.assertNotIn('BetaOut', result.stdout)
            self.assertEqual(path.read_bytes(), SAMPLE)
            self.assertEqual(len(list(d.iterdir())), 1)

    def test_plan_apply_requires_explicit_confirmation(self):
        with scratch() as d:
            path = d / 'Customer.config'; path.write_bytes(SAMPLE)
            key = cm.Document(SAMPLE).connectors[0].key
            plan = d / 'review.json'
            result = self.run_cli('plan', path, '--disable', key, '--environment', 'test', '--out', plan)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_bytes(), SAMPLE)
            denied = self.run_cli('apply', path, '--plan', plan)
            self.assertEqual(denied.returncode, 2)
            self.assertEqual(path.read_bytes(), SAMPLE)
            applied = self.run_cli('apply', path, '--plan', plan, '--apply', '--writers-coordinated')
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual(len(list(d.glob('*.bak'))), 1)

    def test_production_cli_ack_required_again_on_apply(self):
        with scratch() as d:
            path = d / 'Prod.Customer.config'; path.write_bytes(SAMPLE)
            key = cm.Document(SAMPLE).connectors[0].key
            plan = d / 'review.json'
            result = self.run_cli('plan', path, '--disable', key, '--environment', 'test', '--ack-production', '--out', plan)
            self.assertEqual(result.returncode, 0, result.stderr)
            denied = self.run_cli('apply', path, '--plan', plan, '--apply', '--writers-coordinated')
            self.assertEqual(denied.returncode, 2)
            self.assertEqual(path.read_bytes(), SAMPLE)
            applied = self.run_cli('apply', path, '--plan', plan, '--apply', '--ack-production', '--writers-coordinated')
            self.assertEqual(applied.returncode, 0, applied.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
