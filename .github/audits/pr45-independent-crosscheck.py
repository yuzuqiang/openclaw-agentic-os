"""Run from a candidate worktree without modifying it.

This is an independent contract matrix, not proof that every generated source is
executable in every module format. A missing target is a finding candidate that
must be reproduced against the actual runtime before drawing a security conclusion.
Capability-reference-only cases enforce the documented conservative use profile.
"""
import importlib.util
import json
from pathlib import Path

path = Path.cwd() / 'scripts/agentic_os_runtime_source_contract.py'
spec = importlib.util.spec_from_file_location('crosschecked_contract', path)
if spec is None or spec.loader is None:
    raise SystemExit('Cannot load candidate source-contract helper')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cases = []
for module, variable, member in (
    ('node:worker_threads', 'wt', 'Worker'),
    ('node:child_process', 'cp', 'spawnSync'),
    ('node:module', 'M', 'createRequire'),
):
    for acquisition in (f"import * as {variable} from '{module}';", f"const {variable}=require('{module}');"):
        for expression in (variable, f'{variable}.{member}', f"{variable}['{member}']", f'{variable}[`{member}`]', f"{variable}?.['{member}']", f'(({variable})).{member}', f'{variable}[key]'):
            for wrapper in ('const alias=%s;', 'consume(%s);', 'function get(){return %s;}', 'const box={v:%s};', 'const list=[%s];'):
                cases.append(('capability_transfer', acquisition+wrapper%expression, None))
for module, variable, exported in (('node:worker_threads','W','Worker'),('node:child_process','go','spawnSync'),('node:module','c','createRequire')):
    for expression in (variable, f'((({variable})))', f'{variable}.bind(null)', f'(0,{variable})'):
        for wrapper in ('const alias=%s;', 'consume(%s);', 'function get(){return %s;}', 'const box={v:%s};'):
            cases.append(('named_transfer', f"import {{{exported} as {variable}}} from '{module}';"+wrapper%expression, None))
for depth in (0,1,2,4,8):
    base='('*depth+'module'+')'*depth
    for member in ('.require',"['require']",'?.["require"]'):
        cases.append(('module_require_transfer',f"const r={base}{member};r('./hidden.cjs');",'./hidden.cjs'))
for decl in ("import {createRequire} from 'node:module';", "import * as M from 'node:module';", "const M=require('node:module');"):
    factory='createRequire' if '{createRequire}' in decl else 'M.createRequire'
    for expression in (f"const f={factory};const r=f(import.meta.url);r('./hidden.cjs');",f"function get(){{return {factory}(import.meta.url);}}const r=get();r('./hidden.cjs');",f"const r={factory}(import.meta.url).bind(null);r('./hidden.cjs');"):
        cases.append(('factory_transfer',decl+expression,'./hidden.cjs'))
for name in ('return','throw','new','delete','case','else','in','instanceof','typeof','void','of','await','yield'):
    for prefix in ('obj.', 'obj?.', 'this.#'):
        source=prefix+name+" / require('hidden-package') / 2;"
        source=(f'class C{{#{name}=2;go(){{'+source+'}}new C().go();' if prefix=='this.#' else f'const obj={{{name}:2}};'+source)
        cases.append(('keyword_division',source,'hidden-package'))
for expression in ('of','await','yield','value!','value<Type>'):
    cases.append(('contextual_ts_division',expression+" / require('hidden-package') / 2;",'hidden-package'))
for prefix in ('debugger\n','debugger\r','debugger\u2028','debugger\u2029', 'while(false){break\n','while(false){continue\n','outer:while(false){break outer\n'):
    suffix='}\n' if '{' in prefix else ''
    cases.append(('asi_regex',prefix+'/"/;'+suffix+"require('./hidden.cjs');\n/\"/;",'./hidden.cjs'))
for ending in ('\n','\r','\u2028','\u2029'):
    for opener in ('#!', '<!--', '-->'):
        cases.append(('comment_boundary',opener+' "'+ending+"require('./hidden.cjs');"+ending+'// "','./hidden.cjs'))
for decl in ("import {createRequire} from 'node:module';", "import * as M from 'node:module';", "const M=require('node:module');"):
    factory='createRequire' if '{createRequire}' in decl else 'M.createRequire'
    for source in (f"const r={factory}(import.meta.url);r('./hidden.cjs');",f"{factory}(import.meta.url)('./hidden.cjs');",f"const s=`${{{factory}(import.meta.url)('./hidden.cjs')}}`;",f"const r={factory}(__filename);r('./hidden.cjs');"):
        cases.append(('factory_binding',decl+source,'./hidden.cjs'))
for base in ('require', '(require)', '((require))', 'module.require', "module['require']", "module?.['require']"):
    cases.append(('require_binding',base+"('./hidden.cjs');",'./hidden.cjs'))
for source in (
    "import {'Worker' as W} from 'node:worker_threads';const X=W;new X('./hidden.cjs');",
    "import {'spawnSync' as go} from 'node:child_process';const X=go;X(process.execPath,['./hidden.cjs']);",
    "import {'createRequire' as c} from 'node:module';const r=c(import.meta.url);r('./hidden.cjs');",
    "const M=(require)('node:module');const r=M.createRequire(__filename);r('./hidden.cjs');",
    "const cp=(require)('node:child_process');cp.spawnSync(process.execPath,['./hidden.cjs']);",
    "const cp=((require))('node:child_process');const go=cp.spawnSync;go(process.execPath,['./hidden.cjs']);",
    "import{createRequire}from'node:module';const r=createRequire(import.meta.url);const s=`a ${`b ${r('./hidden.cjs')}`}`;",
):
    cases.append(('acquisition_variants',source,'./hidden.cjs'))
failures=[]
rejected=bound=0
for kind,source,target in cases:
    try:
        deps=mod.import_specifiers(source)
    except mod.RuntimeSourceContractError:
        rejected+=1
        continue
    except Exception as exc:
        failures.append({'kind':kind,'source':source,'exception':repr(exc)})
        continue
    if target and any(record[0]==target for record in deps):
        bound+=1
    else:
        failures.append({'kind':kind,'source':source,'dependencies':deps})
print(json.dumps({'source_path':str(path),'cases':len(cases),'rejected':rejected,'bound':bound,'failures':failures},indent=2))
raise SystemExit(bool(failures))
