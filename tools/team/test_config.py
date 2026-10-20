"""Config tooling tests use generated local fixtures, never real credentials."""
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from dotenv import dotenv_values

class ConfigToolTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='team-config-test-')
        self.addCleanup(self.folder.cleanup)
        self.source = Path(self.folder.name) / '.env.source'
        self.target = Path(self.folder.name) / '.env.team'
        names = ('users', 'assets', 'incidents', 'threats', 'logs', 'reports', 'vulnerabilities', 'notifications', 'playbooks')
        self.tokens = {name: secrets.token_hex(32) for name in names}
        self.secret = secrets.token_hex(32)
        self.values = {'DATABASE_URL': 'postgresql+psycopg://fixture@localhost/fixture_test',
                       'JWT_SECRET_KEY': self.secret, 'SERVICE_TOKENS': json.dumps(self.tokens),
                       'ADMIN_PASSWORD': "local ' quoting \\ roundtrip!"}
        self.write_source()

    def write_source(self):
        quote = lambda value: "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"
        self.source.write_text(''.join(key+'='+quote(value)+'\n' for key,value in self.values.items()), encoding='utf-8')

    def run_tool(self):
        return subprocess.run([sys.executable, str(Path(__file__).with_name('init_env.py')), '--source', str(self.source),
                               '--destination', str(self.target)], capture_output=True, text=True)

    def test_coordinated_private_copy_roundtrips_without_secret_output(self):
        original = self.source.read_bytes()
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertNotIn(self.secret, result.stdout+result.stderr)
        values = dotenv_values(self.target)
        self.assertEqual(values['ADMIN_PASSWORD'], self.values['ADMIN_PASSWORD'])
        self.assertEqual(values['CHRIS_JWT_VERIFICATION_KEY'], self.secret)
        self.assertEqual(values['KARIM_JWT_VERIFICATION_KEY'], self.secret)
        self.assertEqual(json.loads(values['CHRIS_SERVICE_TOKENS']), self.tokens)
        self.assertEqual(values['KARIM_INCIDENTS_SERVICE_KEY'], self.tokens['incidents'])
        self.assertTrue(values['KARIM_DATABASE_URL'].startswith('postgresql://'))
        self.assertTrue(values['KARIM_ASSETS_URL'].endswith('/api/chris-gharfine'))

    def test_existing_destination_is_preserved(self):
        self.target.write_text('preserve-existing-file', encoding='utf-8')
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertEqual(self.target.read_text(), 'preserve-existing-file')

    def test_placeholder_or_duplicate_keys_are_rejected(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                tokens = self.tokens.copy()
                tokens['users'] = tokens['assets'] if duplicate else 'CHANGE_ME'
                self.values['SERVICE_TOKENS'] = json.dumps(tokens)
                self.write_source()
                result = self.run_tool()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.target.exists())
                self.assertNotIn(self.secret, result.stdout+result.stderr)

if __name__ == '__main__':
    unittest.main()
