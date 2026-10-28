"""Exercise Debian acceptance orchestration without a Docker daemon or network."""

from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/debian_smoke.py'
FAKE = r'''#!/usr/bin/env python3
from pathlib import Path
import json, os, re, sys
p=Path(os.environ['FAKE_DOCKER_STATE']); s=json.loads(p.read_text()); args=sys.argv[1:]
if args[0].startswith('--host='): args=args[1:]
s.setdefault('calls',[]).append(args)
def done(code=0,output=''):
 p.write_text(json.dumps(s)); print(output,end=''); sys.exit(code)
if args[0]=='build':
 text=(Path(args[-1])/'Dockerfile').read_text()
 s['docs_include_paths']=re.findall(r"'path-include=([^']+)'",text)
 s['docs_included']=set(s['docs_include_paths'])=={'/usr/share/doc/secretwright','/usr/share/doc/secretwright/*'}
 done()
if args[0]=='run': s['running']=True; done(output='c'*64+'\n')
if args[:2]==['rm','--force']: s['running']=False; s['cleaned_container']=True; done()
if args[:3]==['image','rm','--force']: s['cleaned_image']=True; done()
if args[0]=='exec':
 i=1
 while args[i].startswith('--'):
  i+=2
 words=args[i+1:]
 if words[:2]==['dpkg','--install']:
  s['installs']=s.get('installs',0)+1; s['installed']=True; done()
 if words[:2]==['dpkg','--purge']: s['installed']=False; s['purged']=True; done()
 if words[:2]==['dpkg','--verify']: done(output='missing /usr/share/doc/secretwright/README.md\n' if not s.get('docs_included') else 'changed\n' if s.get('bad_integrity') else '')
 if words[:2]==['dpkg','--compare-versions']: done()
 if words[0]=='dpkg-query': done(output='secretwright\n'+('9.9.9' if s.get('bad_metadata') else '0.1.0~rc.7')+'\namd64\ninstall ok installed\n')
 if words[0]=='stat': done(output='0:0:755\n')
 if words[0]=='test': done(1 if s.get('installed') else 0)
 if words[0]=='/usr/bin/secretwright':
  cmd=words[1:]
  if cmd==['version']: done(output='secretwright 0.1.0-rc.7\n')
  if cmd==['--help']: done(output='usage\n')
  if cmd[-1]=='schema': done(output='{}' if s.get('bad_schema') else '{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"fixture"}')
  if cmd==['keytab','example']: done(output='api_version: secretwright/keytab-policy/v1\n')
 done(1)
done(1)
'''

class DebianSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='secretwright-debian-smoke-test-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.bundle=self.root/'bundle'; self.bundle.mkdir()
        self.deb=self.bundle/'secretwright_0.1.0~rc.7_amd64.deb'; self.deb.write_bytes(b'fixture')
        binary=self.root/'docker'; binary.write_text(FAKE); binary.chmod(0o755)
        self.state_path=self.root/'state.json'; self.state={}
        self.env=dict(os.environ,PATH=str(self.root)+os.pathsep+os.environ.get('PATH',''),FAKE_DOCKER_STATE=str(self.state_path))

    def invoke(self):
        self.state_path.write_text(json.dumps(self.state))
        result=subprocess.run([sys.executable,str(SCRIPT),str(self.bundle),'--version','0.1.0-rc.7'],env=self.env,capture_output=True,text=True)
        self.state=json.loads(self.state_path.read_text())
        self.assertNotIn('Traceback',result.stderr)
        return result

    def test_installs_reinstalls_checks_and_purges_inside_offline_container(self):
        result=self.invoke(); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state['installs'],2)
        self.assertTrue(self.state['purged'] and self.state['cleaned_container'] and self.state['cleaned_image'])
        run=next(c for c in self.state['calls'] if c[0]=='run')
        self.assertIn('none',run); self.assertTrue(any('readonly' in value for value in run))
        report=json.loads(result.stdout); self.assertEqual(report['debian_version'],'0.1.0~rc.7'); self.assertTrue(report['purged'])

    def test_debian_slim_doc_exclusion_is_overridden_only_for_package_docs(self):
        result=self.invoke(); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(set(self.state['docs_include_paths']),
                         {'/usr/share/doc/secretwright','/usr/share/doc/secretwright/*'})
        self.assertTrue(self.state['docs_included'])
        self.assertEqual(self.state['installs'],2)

    def test_wrong_installed_metadata_is_rejected_and_cleaned(self):
        self.state['bad_metadata']=True
        result=self.invoke(); self.assertNotEqual(result.returncode,0)
        self.assertTrue(self.state['cleaned_container'] and self.state['cleaned_image'])

    def test_installed_file_integrity_failure_is_rejected(self):
        self.state['bad_integrity']=True
        result=self.invoke(); self.assertNotEqual(result.returncode,0)
        self.assertTrue(self.state['cleaned_container'] and self.state['cleaned_image'])

    def test_invalid_installed_schema_is_rejected(self):
        self.state['bad_schema']=True
        result=self.invoke(); self.assertNotEqual(result.returncode,0)
        self.assertTrue(self.state['cleaned_container'] and self.state['cleaned_image'])

    def test_symlink_package_never_reaches_docker(self):
        original=self.root/'other.deb'; self.deb.rename(original); self.deb.symlink_to(original)
        result=self.invoke(); self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.state.get('calls'))

if __name__=='__main__': unittest.main()
