"""Domain-disjoint, URL-shape-bias-resistant retraining. Never use public submissions as labels.

Only hostname/transport features enter the classifier: ordinary paths, query strings,
slash counts and the 'www' character-run shortcut cannot alone change its probability.
All 30 features remain available to the separate lexical-rule/explanation layer.
Curated live-web samples are weak benign references, never a guarantee of page safety.
"""
import argparse,json,sys,hashlib
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from app.features import normalize,extract,NAMES,VERSION
from train import metrics
ACTIVE=['hostname_length','subdomain_count','is_ip','is_https','nonstandard_port','punycode','brand_match','shortener','host_digit_ratio']
def run(csv,web,out):
 out=Path(out);out.mkdir(parents=True,exist_ok=True)
 rows=json.loads(Path(web).read_text())
 reserved={r['domain'] for r in rows} # ALL collected web domains kept out of historical partitions
 df=pd.read_csv(csv,usecols=['URL','label']);bad=set(df.groupby('URL').label.nunique().loc[lambda x:x>1].index)
 df=df[~df.URL.isin(bad)].drop_duplicates('URL')
 cache=out/'historical-features.npz'
 fingerprint=hashlib.sha256(Path(csv).read_bytes()+Path(web).read_bytes()).hexdigest()
 if cache.exists() and 'fingerprint' in np.load(cache) and str(np.load(cache)['fingerprint'])==fingerprint:
  a=np.load(cache);X,y,g=a['X'],a['y'],a['g']
 else:
  xx=[];yy=[];gg=[]
  for r in df.itertuples(index=False):
   try:n=normalize(r.URL);f=extract(n)
   except (ValueError,UnicodeError):continue
   if n['domain'] in reserved:continue
   xx.append([f[k] for k in NAMES]);yy.append(int(r.label==0));gg.append(n['domain'])
  X,y,g=np.array(xx),np.array(yy),np.array(gg)
  np.savez_compressed(cache,X=X,y=y,g=g,fingerprint=fingerprint)
 train,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(X,y,g))
 ci,ti=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(X[rest],y[rest],g[rest]));cal0,test=rest[ci],rest[ti]
 ci,vi=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=44).split(X[cal0],y[cal0],g[cal0]));cal,val=cal0[ci],cal0[vi]
 parts={'train':train,'calibration':cal,'validation':val,'test':test}
 assert all(not(set(g[a])&set(g[b])) for i,a in enumerate(parts.values()) for b in list(parts.values())[i+1:])
 # Domain assignment fixed before fitting; no external test URL is used here.
 live=[r for r in rows if r['split']=='train' and r.get('source_status')==200]
 domains=sorted({r['domain'] for r in live});rng=np.random.default_rng(20261024);rng.shuffle(domains)
 n=len(domains);sets={'train':set(domains[:max(1,int(n*.6))]),'calibration':set(domains[max(1,int(n*.6)):int(n*.8)]),'validation':set(domains[int(n*.8):])}
 assert all(sets[k] for k in sets)
 mask=np.array([k in ACTIVE for k in NAMES],dtype=float)
 data={};counts={}
 for part,ids in parts.items():
  extra=[r for r in live if r['domain'] in sets.get(part,set())]
  xf=np.array([[extract(normalize(r['url']))[k] for k in NAMES] for r in extra]).reshape(-1,len(NAMES))
  xp=np.concatenate([X[ids],xf]);yp=np.concatenate([y[ids],np.zeros(len(extra),dtype=int)])
  weights=np.ones(len(yp));weights[len(ids):]=max(1,len(ids)*.2/max(1,len(extra)))
  data[part]=(xp,yp,weights,len(ids));counts[part]={'historical_rows':len(ids),'live_reference_rows':len(extra),'historical_domains':len(set(g[ids])),'live_reference_domains':sorted(sets.get(part,set()))}
 scaler=StandardScaler().fit(data['train'][0],sample_weight=data['train'][2])
 def z(x):return scaler.transform(x)*mask
 candidates=[]
 for c in [.01,.1,1.0]:
  lr=LogisticRegression(C=c,max_iter=2000,class_weight='balanced',random_state=42).fit(z(data['train'][0]),data['train'][1],sample_weight=data['train'][2])
  cx,cy,cw,_=data['calibration'];calibrator=LogisticRegression(C=1e6).fit(lr.decision_function(z(cx)).reshape(-1,1),cy,sample_weight=cw)
  vx,vy,_,vn=data['validation'];p=calibrator.predict_proba(lr.decision_function(z(vx)).reshape(-1,1))[:,1]
  choices=[]
  for t in np.arange(.1,.96,.01):
   m=metrics(vy[:vn],p[:vn],t);live_fpr=float(np.mean(p[vn:]>=t))
   if m['fpr']<=.03 and live_fpr<=.05:choices.append((m['f2'],float(t),m,live_fpr))
  if choices:
   score,t,m,fp=max(choices,key=lambda x:x[0]);candidates.append((score,lr,calibrator,t,{'C':c,'historical_validation':m,'live_validation_fpr':fp}))
  print('candidate',c,'eligible',len(choices),flush=True)
 if not candidates:raise RuntimeError('No candidate meets validation false-positive constraints; do not deploy')
 _,lr,calibrator,threshold,selection=max(candidates,key=lambda x:x[0])
 tx,ty,_,_=data['test'];p=calibrator.predict_proba(lr.decision_function(z(tx)).reshape(-1,1))[:,1];test_metrics=metrics(ty,p,threshold)
 model={'version':'domain-lr-v2','feature_version':VERSION,'names':NAMES,'active_features':ACTIVE,'mean':scaler.mean_.tolist(),'scale':scaler.scale_.tolist(),'coef':(lr.coef_[0]*mask).tolist(),'intercept':float(lr.intercept_[0]),'calibration_coef':float(calibrator.coef_[0][0]),'calibration_intercept':float(calibrator.intercept_[0]),'threshold':threshold,'metrics':test_metrics,'training_rows':len(data['train'][1]),'test_rows':len(ty),'calibration_scope':'Domain-disjoint historical PhiUSIIL plus curated live benign references; not a live safety probability','model_scope':'9 hostname/transport predictors; all 30 URL features remain available for warning rules. URL paths and query strings do not change the model-only score.'}
 report={'version':model['version'],'dataset_sha256':hashlib.sha256(Path(csv).read_bytes()).hexdigest(),'web_manifest_sha256':hashlib.sha256(Path(web).read_bytes()).hexdigest(),'active_features':ACTIVE,'split':counts,'domain_overlap':0,'external_test_used_for_training_or_selection':False,'selection':selection,'threshold':threshold,'logistic_test':test_metrics,'limitations':['Historical phishing examples; no live malicious recall estimate','Live benign references are curated source URLs, not forensic safety labels','Model ignores page content and path semantics; lexical rules inspect full URL separately','Probability calibration applies only to the weighted evaluation mixture','URLs on compromised/shared hosting may evade hostname-based detection'],'web_training_sources':sorted({r['source'] for r in live})}
 (out/'model.json').write_text(json.dumps(model,indent=2));(out/'evaluation.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--csv',required=True);p.add_argument('--web',required=True);p.add_argument('--out',required=True);a=p.parse_args();run(a.csv,a.web,a.out)
