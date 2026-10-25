import fs from 'node:fs';
import ts from 'typescript';
import assert from 'node:assert/strict';
let source=fs.readFileSync('lib/analysis.ts','utf8').replace("import model from '../artifacts/model.json';",'const model='+fs.readFileSync('artifacts/model.json','utf8')+';').replace("import rules from './psl.json';",'const rules='+fs.readFileSync('lib/psl.json','utf8')+';');
const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const {normalize,extract,analyze}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
const fixtures=JSON.parse(fs.readFileSync('tests/parity.json','utf8'));
let mismatches=[];
for(const x of fixtures){
 try{const n=normalize(x.input),f=extract(n),r=analyze(x.input);assert.equal(n.domain,x.domain);for(const [k,v] of Object.entries(x.features))assert.ok(Math.abs(f[k]-v)<1e-7,k+': '+f[k]+' vs '+v);assert.ok(Math.abs(r.model.probability-x.probability)<1e-6);}catch(e){mismatches.push({input:x.input,error:e.message});}
}
console.log(JSON.stringify({cases:fixtures.length,mismatches:mismatches.length,examples:mismatches.slice(0,12)},null,2));if(mismatches.length)process.exit(1);
// Exercise the actual hosted scorer against the frozen current-web regression set.
const references=JSON.parse(fs.readFileSync('tests/data/real-web-2026-10-24.json','utf8')).filter(x=>x.split==='test');
assert.equal(references.length,500);
const falseWarnings=references.filter(x=>analyze(x.url).risk_score>=35);
assert.deepEqual(falseWarnings,[],'Unexpected warnings on curated reference URLs');
for(const u of ['https://github.com.attacker.test/Manieshsekar','https://coursera.org.attacker.test/learn','https://secure-github-login.test/login/verify'])assert.ok(analyze(u).risk_score>=35,'Imitation must remain a warning: '+u);
console.log(JSON.stringify({hosted_reference_urls:references.length,reference_warnings:falseWarnings.length,platform_imitation_checks:3}));
