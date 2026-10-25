import sys,json,random,time,concurrent.futures,urllib.parse,urllib.request
from html.parser import HTMLParser
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from app.features import normalize
class Links(HTMLParser):
 def __init__(self):super().__init__();self.links=[]
 def handle_starttag(self,tag,attrs):
  if tag=='a':self.links.extend(v for k,v in attrs if k=='href' and v)
SEEDS={
 'test':[
 'https://docs.python.org/3/library/index.html','https://developer.mozilla.org/en-US/docs/Web','https://www.coursera.org/learn/machine-learning','https://github.com/Manieshsekar','https://en.wikipedia.org/wiki/Machine_learning',
 'https://www.nasa.gov/','https://www.bbc.com/','https://www.britannica.com/','https://www.mit.edu/','https://www.stanford.edu/','https://www.harvard.edu/','https://www.ox.ac.uk/','https://www.un.org/en/','https://www.who.int/','https://www.worldbank.org/','https://www.imf.org/en/Home','https://www.nist.gov/','https://www.gov.uk/','https://www.loc.gov/','https://www.khanacademy.org/','https://www.edx.org/','https://www.nature.com/','https://www.scientificamerican.com/','https://www.theguardian.com/international','https://www.reuters.com/','https://www.nationalgeographic.com/','https://www.esa.int/','https://www.cern.ch/','https://www.si.edu/','https://www.w3.org/','https://www.rfc-editor.org/','https://www.gnu.org/','https://www.libreoffice.org/','https://www.openstreetmap.org/about','https://www.duckduckgo.com/','https://www.youtube.com/','https://www.google.com/','https://www.linkedin.com/','https://www.microsoft.com/','https://www.apple.com/'],
 'train':[
 'https://numpy.org/doc/stable/reference/index.html','https://pandas.pydata.org/docs/reference/index.html','https://docs.scipy.org/doc/scipy/reference/index.html','https://scikit-learn.org/stable/api/index.html','https://pytorch.org/docs/stable/index.html','https://www.tensorflow.org/api_docs/python/tf','https://react.dev/reference/react','https://nextjs.org/docs','https://www.postgresql.org/docs/current/index.html','https://www.sqlite.org/docs.html','https://redis.io/docs/latest/','https://docs.docker.com/','https://kubernetes.io/docs/home/','https://go.dev/doc/','https://www.rust-lang.org/learn','https://www.djangoproject.com/start/','https://flask.palletsprojects.com/en/stable/','https://fastapi.tiangolo.com/','https://www.php.net/docs.php','https://www.ruby-lang.org/en/documentation/']}
ROOT=Path('work/scoring-fix');UA='ThreatLens-Validation/1.0 (bounded academic URL validation; no authentication)'
def fetch(url,body=True):
 try:
  req=urllib.request.Request(url,headers={'User-Agent':UA})
  with urllib.request.urlopen(req,timeout=10) as r:
   data=r.read(1200000) if body else b'';return r.status,r.url,data.decode('utf-8','replace'),None
 except Exception as e:return getattr(e,'code',None),url,'',str(e)[:120]
def collect(item):
 split,seed=item;status,final,html,error=fetch(seed);rows=[]
 if status!=200:return {'seed':seed,'split':split,'status':status,'error':error,'rows':[]}
 parser=Links();parser.feed(html);host=urllib.parse.urlsplit(final).hostname
 # Keep links published by the seed site and on that exact host. No arbitrary outbound crawling.
 pool={urllib.parse.urldefrag(urllib.parse.urljoin(final,h))[0] for h in parser.links}
 pool={u for u in pool if urllib.parse.urlsplit(u).scheme=='https' and urllib.parse.urlsplit(u).hostname==host and not urllib.parse.urlsplit(u).query and not any(u.lower().endswith(e) for e in ['.pdf','.zip','.png','.jpg','.svg','.mp4','.gz'])}
 pool.discard(final);pool=sorted(pool);random.Random(20261024).shuffle(pool)
 candidates=[final]+pool[:24 if split=='test' else 34]
 for u in candidates:
  try:n=normalize(u)
  except ValueError:continue
  rows.append({'url':u,'domain':n['domain'],'source':seed,'source_status':status,'split':split,'label':0,'label_basis':'Curated official/educational/editorial source link; not a malware guarantee','checked_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})
 return {'seed':seed,'split':split,'status':status,'rows':rows}
if __name__=='__main__':
 results=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
  for r in ex.map(collect,[(s,u) for s,urls in SEEDS.items() for u in urls]):
   results.append(r);print(r['split'],r['seed'],r['status'],len(r['rows']),flush=True)
 ROOT.joinpath('web-sources.json').write_text(json.dumps(results,indent=2))
 rows=[x for r in results for x in r['rows']]
 # Round robin across domains, cap evaluation at 500; freeze before fitting.
 test=[r['rows'] for r in results if r['split']=='test'];selected=[]
 for i in range(25):
  selected.extend(a[i] for a in test if len(a)>i)
 selected=selected[:500]
 train=[x for x in rows if x['split']=='train']
 ROOT.joinpath('web-candidates.json').write_text(json.dumps(train+selected,indent=2))
 print('FROZEN',len(train),len(selected),flush=True)
 def check(r):
  status,final,_,error=fetch(r['url'],body=False);return {**r,'http_status':status,'final_url':final,'fetch_error':error}
 checked=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
  for i,r in enumerate(ex.map(check,train+selected)):
   checked.append(r)
   if i%100==0:print('checked',i,flush=True)
 ROOT.joinpath('web-checked.json').write_text(json.dumps(checked,indent=2))
 print('DONE',len(checked),'HTTP200',sum(r['http_status']==200 for r in checked),flush=True)
