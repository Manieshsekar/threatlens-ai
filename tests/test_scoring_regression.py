"""Public false-positive regression and adversarial URL handling.
These benign-reference checks are not a malicious-URL accuracy estimate.
"""
import json,sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from app.features import normalize
from app.engine import assess
ROOT=Path(__file__).resolve().parents[1]
@pytest.mark.parametrize('url',[
 'https://github.com/Manieshsekar',
 'https://www.coursera.org/learn/machine-learning',
 'https://docs.python.org/3/library/json.html',
 'https://en.wikipedia.org/wiki/Machine_learning',
])
def test_reported_false_positives(url):
 assert assess(normalize(url))['risk_score']<35

def test_paths_cannot_drive_model_probability():
 for host in ['github.com','www.coursera.org','unseen-domain.example']:
  base=assess(normalize('https://'+host))['model']['probability']
  for path in ['/arbitrary/profile','/2026/10/24/news/article','/a/b/c/d?utm_source=mail&search=testing','/login/verify?redirect=https://elsewhere.test']:
   assert assess(normalize('https://'+host+path))['model']['probability']==base

def test_warning_rules_still_examine_path():
 a=assess(normalize('https://example.com'))
 b=assess(normalize('https://example.com/login/verify/update.exe?redirect=https://elsewhere.test'))
 assert b['risk_score']>=35 and len(b['signals'])>len(a['signals'])

def test_impersonation_and_ip_not_allowlisted():
 for u in ['https://github.com.attacker.test/Manieshsekar','https://coursera.org.attacker.test/learn','https://secure-github-login.test/login/verify','https://paypal-login.verify-account.attacker.test/login/verify','http://192.0.2.1/login/verify/account']:
  assert assess(normalize(u))['risk_score']>=35

def test_frozen_real_web_reference_set():
 rows=[r for r in json.loads((ROOT/'tests/data/real-web-2026-10-24.json').read_text()) if r['split']=='test']
 assert len(rows)==500 and len({r['domain'] for r in rows})>=30
 reports=[assess(normalize(r['url'])) for r in rows]
 assert sum(r['risk_score']>=35 for r in reports)==0

def test_no_live_test_domains_in_learning_partitions():
 rows=json.loads((ROOT/'tests/data/real-web-2026-10-24.json').read_text())
 a={r['domain'] for r in rows if r['split']=='test'};b={r['domain'] for r in rows if r['split']=='train'}
 assert not a&b
 report=json.loads((ROOT/'artifacts/evaluation.json').read_text())
 for part in ['train','calibration','validation']:
  assert not a&set(report['split'][part]['live_reference_domains'])
