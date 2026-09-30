import model from '../artifacts/model.json';
import rules from './psl.json';
const suffixes=new Set(rules);
const words=['login','signin','verify','account','password','secure','update','confirm','wallet','payment','bank'];
const brands=['paypal','microsoft','google','apple','amazon','netflix','facebook','instagram'];
const shorteners=new Set(['bit.ly','t.co','tinyurl.com','goo.gl','is.gd','ow.ly']);
const count=(s:string,re:RegExp)=>(s.match(re)||[]).length;
const length=(s:string)=>Array.from(s).length;
export type Observation={provider:string;status:string;detail:string;malicious?:boolean|null;[key:string]:unknown};
export type Report={id:string;url:string;hostname:string;domain:string;classification:string;risk_score:number;confidence:string;model:{version:string;probability:number;threshold:number;classification:string;calibration_scope?:string};signals:{title:string;detail:string;weight:number;source:string}[];features:Record<string,number>;explanation:{feature:string;contribution:number;direction:string}[];observations:Observation[];recommendation:string;score_method:string;created_at:string;status:string;mode:string;verification?:{verdict:string;note:string;analyst:string;at:string};review_history?:{action:string;at:string}[];feedback?:{category:string;note:string;at:string};verification_conflict?:boolean};
export function domainParts(host:string){
 const labels=host.split('.');let size=1,known=false;
 for(let i=0;i<labels.length;i++){
  const tail=labels.slice(i).join('.');
  if(suffixes.has('!'+tail)){known=true;size=labels.length-i-1;break;}
  if(suffixes.has(tail)){known=true;size=Math.max(size,labels.length-i);}
  if(i>0&&suffixes.has('*.'+tail)){known=true;size=Math.max(size,labels.length-i+1);}
 }
 return known?{domain:labels.slice(-size-1).join('.'),subdomains:Math.max(0,labels.length-size-1)}:{domain:host,subdomains:labels.length-1};
}
export function normalize(raw:string){
 if(typeof raw!=='string'||!raw.trim()||raw.length>4096)throw Error('Enter a URL between 1 and 4096 characters.');
 raw=raw.trim();if(/[\x00-\x20\x7f\\]/.test(raw))throw Error('Whitespace, control characters and backslashes are not accepted.');
 if(!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw))raw='https://'+raw;
 let u:URL;try{u=new URL(raw);}catch{throw Error('Invalid URL or hostname.');}
 if(!['http:','https:'].includes(u.protocol)||!u.hostname)throw Error('Only HTTP and HTTPS URLs are supported.');
 if(u.username||u.password)throw Error('URLs containing credentials are not accepted.');
 const authority=raw.split('://')[1].split(/[/?#]/)[0];let inputHost=authority.replace(/:\d+$/,'').replace(/^\[|\]$/g,'');
 if(inputHost.includes('%'))throw Error('Encoded hosts and IPv6 zone identifiers are not accepted.');
 let host=u.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,'').toLowerCase();
 if(/^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$/i.test(inputHost)&&!/^\d{1,3}(\.\d{1,3}){3}$/.test(inputHost))throw Error('Noncanonical numeric addresses are not accepted.');
 if(/^\d{1,3}(\.\d{1,3}){3}$/.test(inputHost)&&inputHost!==host)throw Error('Noncanonical numeric addresses are not accepted.');
 const isIp=host.includes(':')||/^\d+(\.\d+){3}$/.test(host);
 if(!isIp&&(host.length>253||host.split('.').some(s=>!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s))))throw Error('Invalid domain name.');
 if(u.port==='0')throw Error('Port zero is not supported.');
 const m=raw.match(/^[^:]+:\/\/[^/?#]+([^?#]*)(?:\?([^#]*))?/);const path=m?.[1]||'/';const query=m?.[2]||'';
 const hostport=(host.includes(':')?'['+host+']':host)+(u.port?':'+u.port:'');const canonical=u.protocol+'//'+hostport+path+(query?'?'+query:'');
 // All literal addresses are blocked from hosted network lookups, including unusual IPv6 ranges.
 const parts=isIp?{domain:host,subdomains:0}:domainParts(host);
 return {canonical,hostname:host,...parts,scheme:u.protocol.slice(0,-1),port:u.port?Number(u.port):null,path,query,is_ip:isIp,is_private:isIp||host==='localhost'||/\.(localhost|local|internal)$/.test(host)};
}
export function extract(n:ReturnType<typeof normalize>){
 const u=n.canonical,h=n.hostname;let lower=u.toLowerCase();try{lower=decodeURIComponent(u).toLowerCase();}catch{/* malformed encoding stays literal */}
 const digits=count(u,/\p{Nd}/gu),letters=count(u,/\p{L}/gu),freq:Record<string,number>={};for(const c of u)freq[c]=(freq[c]||0)+1;
 const entropy=-Object.values(freq).reduce((s,v)=>s+(v/length(u))*Math.log2(v/length(u)),0);
 const vals=[length(u),length(h),length(n.path),length(n.query),n.subdomains,count(u,/\./g),count(u,/-/g),count(u,/_/g),count(u,/\//g),digits,letters,digits/length(u),letters/length(u),entropy,+n.is_ip,+(n.scheme==='https'),+(n.port!==null&&![80,443].includes(n.port)),+h.includes('xn--'),count(u,/%/g),n.query?n.query.split('&').length:0,Math.max(...(u.match(/(.)\1*/gu)||['']).map(length)),+/\.(exe|scr|zip|apk|iso)(?:$|[?])/.test(lower),words.reduce((s,w)=>s+lower.split(w).length-1,0),brands.filter(b=>h.includes(b)&&n.domain!==b+'.com').length,+shorteners.has(n.domain),+/(?:^|&)(?:url|redirect|next|continue|return|dest)=/i.test(n.query),count(u,/@/g),count(u,/=/g),count(u,/\?/g),count(h,/\p{Nd}/gu)/length(h)];
 return Object.fromEntries(model.names.map((k,i)=>[k,vals[i]]));
}
export function analyze(raw:string):Report{
 const n=normalize(raw),f=extract(n),values=model.names.map((k,i)=>(f[k]-model.mean[i])/model.scale[i]*model.coef[i]);
 const logit=model.intercept+values.reduce((a,b)=>a+b,0),p=1/(1+Math.exp(-Math.max(-700,Math.min(700,logit*model.calibration_coef+model.calibration_intercept))));
 const signals:Report['signals']=[];const add=(ok:unknown,title:string,detail:string,weight:number)=>{if(ok)signals.push({title,detail,weight,source:'lexical rule'});};
 add(f.brand_match,'Brand reference outside its standard domain','A brand name appears in this hostname. It may be imitation or a legitimate reference.',25);
 add(f.is_ip,'IP address used as host','An IP literal replaces a domain; legitimate infrastructure may do this too.',15);
 add(f.punycode,'Internationalized domain','Inspect the displayed name carefully for imitation. Punycode alone is not malicious.',10);
 add(f.credential_words>=2,'Multiple account-related terms','Several login, payment or security words occur in the URL.',15);
 add(f.subdomain_count>=3,'Deeply nested hostname','Many subdomains can obscure the registrable domain.',10);
 add(f.nonstandard_port,'Unusual web port','The URL uses a port other than 80 or 443.',5);
 add(!f.is_https,'Unencrypted URL scheme','HTTP does not protect traffic in transit; this alone does not establish phishing.',10);
 add(f.url_length>160,'Long URL','Long URLs can obscure destinations; legitimate tracking links can also be long.',5);
 add(f.redirect_parameter,'Redirect parameter','A destination-like parameter is present. No redirect was followed.',5);
 add(f.suspicious_extension,'Download-like path','The path suggests an executable or archive.',15);
 add(n.is_private,'Network inspection blocked','Literal addresses and nonpublic names are not sent to network collectors.',0);
 const risk=Math.round(Math.max(p*100,Math.min(100,signals.reduce((s,x)=>s+x.weight,0)))*10)/10;
 return {id:crypto.randomUUID(),url:n.scheme+'://'+(n.hostname.includes(':')?'['+n.hostname+']':n.hostname)+(n.port?':'+n.port:'')+(n.path==='/'?'/':'/[path redacted]')+(n.query?'?[query redacted]':''),hostname:n.hostname,domain:n.domain,classification:risk>=75?'high risk':risk>=35?'suspicious':'low risk',risk_score:risk,confidence:'limited',model:{version:model.version,probability:Math.round(p*1e6)/1e6,threshold:model.threshold,classification:p>=model.threshold?'phishing':'legitimate',calibration_scope:'historical PhiUSIIL benchmark'},signals,features:f,explanation:model.names.map((k,i)=>({feature:k,contribution:Math.round(values[i]*1e4)/1e4,direction:values[i]>0?'raises':'lowers'})).sort((a,b)=>Math.abs(b.contribution)-Math.abs(a.contribution)).slice(0,8),observations:[],recommendation:risk>=35?'Avoid entering credentials or downloading files; verify through a known official channel.':'No strong lexical warning was found. Verify the destination before sharing sensitive information.',score_method:'Maximum of the benchmark model score and capped lexical rule points. This fused risk score is not a probability.',created_at:new Date().toISOString(),status:'complete',mode:'quick'};
}
export {model};
