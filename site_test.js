const fs = require('fs'), vm = require('vm'), assert = require('assert');
const html = fs.readFileSync('index.html', 'utf8');
const js = html.match(/<script>([\s\S]*)<\/script>/)[1];

function makeEnv(pingOk, pub) {
  const store = {};
  const els = {}, calls = [];
  function mk(id) {
    const e = {id, children: [], style: {}, dataset: {}, _attrs: {}, _cls: new Set(), value: '', checked: false, disabled: false,
      _html: '', textContent: '', onclick: null, onchange: null, files: [], _qc: {}};
    Object.defineProperty(e, 'innerHTML', {get: () => e._html, set: v => { e._html = v; e._qc = {}; if (v === '') e.children = []; }});
    e.classList = {add: c => e._cls.add(c), remove: c => e._cls.delete(c), contains: c => e._cls.has(c),
      toggle: (c, f) => { if (f === undefined) f = !e._cls.has(c); f ? e._cls.add(c) : e._cls.delete(c); }};
    e.appendChild = c => { e.children.push(c); return c; };
    e.setAttribute = (k, v) => { e._attrs[k] = v; }; e.getAttribute = k => e._attrs[k];
    e.addEventListener = () => {}; e.removeEventListener = () => {}; e.setPointerCapture = () => {};
    e.getBoundingClientRect = () => ({width: 800, height: 500}); e.closest = () => null; e.remove = () => {}; e.select = () => {};
    e.click = () => e.onclick && e.onclick();
    e.querySelectorAll = sel => {            // minimal: find <button class="X" ...> inside the current innerHTML
      const cls = sel.replace('.', ''), key = sel + e._html;
      if (e._qc[key]) return e._qc[key];
      const out = [], re = /<button[^>]*>/g; let m;
      while ((m = re.exec(e._html))) {
        if (new RegExp('class="' + cls + '"').test(m[0])) {
          const b = mk('btn-' + cls); const d = /data-[ik]="(\d+)"/.exec(m[0]);
          if (d) { b.dataset.i = d[1]; b.dataset.k = d[1]; } out.push(b);
        }
      }
      return (e._qc[key] = out);
    };
    return e;
  }
  const tabs = ['start', 'trace', 'site', 'wallet', 'verify', 'ledger', 'labels', 'watch', 'help'].map(t => { const b = mk('tab-' + t); b.dataset.t = t; return b; });
  const panels = tabs.map(t => mk('p-' + t.dataset.t)); 
  const document = {
    getElementById: id => els[id] || (els[id] = mk(id)),
    createElementNS: (ns, t) => mk(t), createElement: t => mk(t), body: mk('body'), documentElement: mk('html'), title: '',
    querySelectorAll: sel => sel === '.tab' ? tabs : sel === '.panel' ? panels : [],
  };
  const fixtures = {};
  const fetch = (url, opts) => {
    calls.push({url, opts: opts || {}});
    if (url.startsWith('/api/ping')) return pingOk ? Promise.resolve({ok: true, json: async () => ({ok: true, public: !!pub})}) : Promise.reject(new Error('offline'));
    const body = fixtures[url.split('?')[0]] || {error: 'no fixture for ' + url};
    const ok = !(body && body.error);
    return Promise.resolve({ok, json: async () => body});
  };
  const ctx = vm.createContext({document, fetch, navigator: {clipboard: {writeText: () => Promise.resolve()}}, URL: {createObjectURL: () => 'blob:x'},
    Blob: class {}, requestAnimationFrame: () => 0, setTimeout, localStorage: {getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = v; }}, URLSearchParams, console, Math, JSON, Promise, Set, Object, String, Array, Error, Number});
  vm.runInContext(js, ctx);
  return {ctx, els, calls, fixtures, tabs, panels, ev: s => vm.runInContext(s, ctx), $: id => document.getElementById(id)};
}
const tick = () => new Promise(r => setTimeout(r, 0));
async function click(env, id) { const r = env.$(id).onclick(); await r; await tick(); }
const GRAPH = {start: 'S', chain: 'btc', nodes: {S: {depth: 0}, A: {depth: 1, label: 'Demo Exchange', category: 'exchange', source: 't', confidence: 'high', taint: 0.5, inferred: 'x'}},
  edges: [{from: 'S', to: 'A', txid: 't1', btc: 1.0, taint: 0.5}], clusters: [['S', 'A']]};

(async () => {
  let n = 0; const ok = (name, cond) => { assert(cond, 'FAILED: ' + name); console.log('PASS  ' + name); n++; };

  // ----- display mode (no local server): the map works, local tools explain themselves
  let env = makeEnv(false); await tick();
  ok('display mode: starts without the local badge', !env.$('mode')._cls.has('on'));
  await click(env, 'demo');
  ok('display mode: the demo map loads (8 nodes drawn)', env.ev('nodes.length') === 8 && env.$('info').innerHTML.includes('بيانات تجريبية'));
  env.$('tx').value = 'a'.repeat(64); await click(env, 'ik');
  ok('display mode: a local-only tool tells the user to run serve.py instead of failing', env.$('info').innerHTML.includes('python serve.py'));
  ok('display mode: no API call was made except the ping', env.calls.every(c => c.url.startsWith('/api/ping')));
  const up = {target: {files: [{text: async () => JSON.stringify(GRAPH)}]}};
  await env.$('file').onchange(up); await tick();
  ok('display mode: uploading graph.json draws it', env.ev('nodes.length') === 2 && env.ev('G.start') === 'S');
  const navHtml = html.slice(html.indexOf('<nav id="tabs">'), html.indexOf('</nav>'));
  const basic = [...navHtml.matchAll(/<button class="tab(?: on)?" data-t="([a-z]+)"/g)].map(m => m[1]), adv = [...navHtml.matchAll(/<button class="tab adv" data-t="([a-z]+)"/g)].map(m => m[1]);
  ok('simplicity: by default only three tabs are visible (start, before you pay, help); the other eight are behind "advanced tools"', basic.join() === 'start,precheck,help' && adv.length === 8 && navHtml.includes('id="advbtn"'));
  ok('simplicity: the advanced tabs start hidden', env.ev("document.body._cls.has('showadv')") === false);
  env.$('advbtn').onclick(); ok('simplicity: the advanced-tools button reveals them', env.ev("document.body._cls.has('showadv')") === true);
  env.$('advbtn').onclick(); ok('simplicity: and hides them again', env.ev("document.body._cls.has('showadv')") === false);
  env.ev("tab('trace')"); ok('simplicity: opening an advanced tab from anywhere (e.g. a button inside a result) reveals the advanced tabs', env.ev("document.body._cls.has('showadv')") === true);
  env.ev("tab('start')"); env.$('advbtn').onclick();
  const apiBefore = env.calls.length;
  env.$('pc_seed_phrase').checked = true; await env.$('pc_go').onclick(); await tick();
  ok('precheck (display mode): a stop flag gives STOP with the advice, computed in the page with no server', env.$('info').innerHTML.includes('توقف') && env.$('info').innerHTML.includes('لا تشارك عبارة الاسترداد') && env.$('info').innerHTML.includes('إن كنت دفعت بالفعل'));
  env.$('pc_seed_phrase').checked = false; env.$('pc_urgency').checked = true; await env.$('pc_go').onclick(); await tick();
  ok('precheck (display mode): a caution flag gives CAUTION (and the stop-only advice is absent)', env.$('info').innerHTML.includes('حذر') && !env.$('info').innerHTML.includes('إن كنت دفعت بالفعل'));
  env.$('pc_urgency').checked = false; env.$('pc_addr').value = '1ABC'; env.$('info').innerHTML = ''; await env.$('pc_go').onclick(); await tick();
  ok('precheck (display mode): an address with no flags says nothing was checked instead of claiming "no flags"', env.$('info').innerHTML.includes('لم يُفحص شيء') && !env.$('info').innerHTML.includes('لا مؤشرات'));
  env.$('pc_seed_phrase').checked = true; await env.$('pc_go').onclick(); await tick();
  ok('precheck (display mode): flags plus an address warn that the address was not checked, and no API call was made', env.$('info').innerHTML.includes('ما لم يُفحص') && env.calls.length === apiBefore);
  env.$('pc_seed_phrase').checked = false; env.$('pc_addr').value = '';


  // ----- local mode: every tool, with fake server answers
  env = makeEnv(true); await tick(); await tick();
  ok('local mode: the badge turns on after the ping', env.$('mode')._cls.has('on'));
  env.tabs[1].onclick(); ok('tabs: clicking a tab shows its panel', env.panels[1]._cls.has('on') && !env.panels[0]._cls.has('on'));
  const F = env.fixtures;
  F['/api/intake'] = {chain: 'btc', txid: 'a'.repeat(64), time_str: '2026-10-10', senders: ['V'], candidates: [{to: '1SCAM', amount: 0.6, asset: 'BTC', vout: 1}, {to: '1CHANGE', amount: 3.9, asset: 'BTC', vout: 0}]};
  F['/api/case'] = {graph: GRAPH, summary: 'تقرير الحقيقة', letters: {'police_report.md': 'REPORT TEXT', 'exchange_notice_x.md': 'LETTER'}, folder: 'cases/1'};
  env.$('tx').value = 'a'.repeat(64); env.$('victim').value = 'علي'; env.$('contact').value = 'a@b.c'; env.$('rno').value = '77/2026';
  await click(env, 'ik');
  ok('start: the candidates of the payment transaction are listed with a pick button', env.$('info').innerHTML.includes('1SCAM') && env.$('info').querySelectorAll('.pk').length === 2);
  env.$('info').querySelectorAll('.pk')[0].onclick(); await tick(); await tick();
  const cc = env.calls.filter(c => c.url.startsWith('/api/case')).pop();
  const q = new URLSearchParams(cc.url.split('?')[1]);
  ok('start: picking the scammer builds the case from the exact outpoint, amount, date and details',
     q.get('address') === '1SCAM' && q.get('vout') === '1' && q.get('txid') === 'a'.repeat(64) && q.get('stolen') === '0.6' && q.get('depth') === '6'
     && q.get('victim') === 'علي' && q.get('contact') === 'a@b.c' && q.get('report_no') === '77/2026' && q.get('incident') === '2026-10-10');
  ok('start: the report and the ready letters are shown', env.$('info').innerHTML.includes('تقرير الحقيقة') && env.$('info').innerHTML.includes('police_report.md'));
  const cp = env.$('info').querySelectorAll('.cp'); ok('start: every letter has a copy button', cp.length === 2);
  await cp[0].onclick(); await tick(); ok('start: copying a letter works', cp[0].textContent === 'تم النسخ');
  ok('start: the map shows the case graph', env.ev('nodes.length') === 2);
  ok('every /api call carries the X-Tracer header', env.calls.filter(c => c.url.startsWith('/api/') && !c.url.startsWith('/api/ping')).every(c => c.opts.headers && c.opts.headers['X-Tracer'] === '1'));

  F['/api/trace'] = GRAPH; env.$('addr').value = '1ABC'; env.$('chain').value = 'btc'; env.$('tn').checked = true; env.$('st').value = '0.6';
  await click(env, 'go'); const tc = env.calls.filter(c => c.url.startsWith('/api/trace')).pop();
  ok('trace: taint mode and the stolen amount are sent', tc.url.includes('taint=1') && tc.url.includes('stolen=0.6') && tc.url.includes('address=1ABC'));
  env.$('addr').value = ''; env.$('info').innerHTML = ''; await click(env, 'go'); ok('trace: an empty address is refused politely', env.$('info').innerHTML.includes('أدخل عنوان'));

  F['/api/scan'] = {report: 'تقرير موقع', tier: 'HIGH', domain: 'x', addresses: [{address: '0xabc', chain: 'eth'}]};
  env.$('su').value = 'https://scam.example'; await click(env, 'sc');
  ok('site: the report and the found wallets are shown', env.$('info').innerHTML.includes('تقرير موقع') && env.$('info').querySelectorAll('.tr').length === 1);
  F['/api/trace'] = GRAPH; env.$('info').querySelectorAll('.tr')[0].onclick(); await tick(); await tick();
  ok('site: the trace button moves the wallet to the trace tab and starts tracing', env.$('chain').value === 'eth' && env.$('addr').value === '0xabc' && env.calls.some(c => c.url.includes('address=0xabc')));

  F['/api/profile'] = {report: 'ملف المحفظة'}; env.$('waddr').value = '1ABC'; await click(env, 'pf2'); ok('wallet: profile is shown', env.$('info').innerHTML.includes('ملف المحفظة'));
  F['/api/operation'] = {lines: ['- عدد الجهات: 6'], ops: {top: [['P1', 2, {}]]}}; await click(env, 'op'); ok('wallet: payer analysis is shown', env.$('info').innerHTML.includes('عدد الجهات'));
  F['/api/patterns'] = {tier: 'HIGH', score: 9, tier_text: 'نمط', findings: [{type: 'FAN_OUT', weight: 3, text: 'وزّع أمواله'}]};
  await click(env, 'pt'); const pc = env.calls.filter(c => c.url.startsWith('/api/patterns')).pop();
  ok('wallet: the current map is POSTed for pattern analysis and findings listed', pc.opts.method === 'POST' && JSON.parse(pc.opts.body).graph.start === 'S' && env.$('info').innerHTML.includes('FAN_OUT'));

  F['/api/verify'] = {report: 'تقرير التحقق', verdict: 'PASS WITH WARNINGS'}; env.$('vnn').checked = true; await click(env, 'vf');
  const vc = env.calls.filter(c => c.url.startsWith('/api/verify')).pop();
  ok('verify: the graph is POSTed with the no-network option and the verdict shown', JSON.parse(vc.opts.body).no_network === true && env.$('info').innerHTML.includes('PASS WITH WARNINGS'));
  F['/api/reports'] = {lines: ['- 3 بلاغات']}; env.$('raddr').value = '1ABC'; await click(env, 'rp'); ok('verify: public reports are shown', env.$('info').innerHTML.includes('3 بلاغات'));
  F['/api/archive-check'] = {ok: true, entries: 12, problems: []}; await click(env, 'ac'); ok('verify: an intact archive is reported', env.$('info').innerHTML.includes('الأرشيف سليم'));
  F['/api/archive-check'] = {ok: true, entries: 1, problems: []}; F['/api/archive-check'] = {ok: false, entries: 2, problems: ['entry 0: file modified']};
  await click(env, 'ac'); ok('verify: a tampered archive is reported with the problem', env.$('info').innerHTML.includes('entry 0: file modified'));

  F['/api/label'] = {status: 'added', address: '1ABC'}; env.$('lb_addr').value = '1ABC'; env.$('lb_name').value = 'X'; env.$('lb_cat').value = 'exchange'; env.$('lb_conf').value = 'low'; await click(env, 'lb_add');
  const lc = env.calls.filter(c => c.url.startsWith('/api/label')).pop();
  ok('labels: a label is POSTed and confirmed', JSON.parse(lc.opts.body).category === 'exchange' && env.$('info').innerHTML.includes('تم الحفظ'));
  F['/api/lookup'] = {address: '1ABC', label: {label: 'X', category: 'exchange', confidence: 'low', source: 'manual'}, sites: [{domain: 's.example', tier: 'HIGH'}], reports: {count: 2}};
  await click(env, 'lk'); ok('labels: lookup shows label, sites and reports', ['X', 's.example', '2'].every(s => env.$('info').innerHTML.includes(s)));
  F['/api/labels-stats'] = {total: 5, categories: {exchange: 3}, conflicts: 1}; await click(env, 'ls'); ok('labels: statistics are shown', env.$('info').innerHTML.includes('5'));

  ok('ledger: building a case fills the case id automatically', env.$('lcase').value === '1');
  F['/api/ledger/cases'] = {cases: [{case_id: '1', claims: 2}]}; await env.ev('loadCases()'); await tick();
  ok('ledger: the known cases are offered in the case list', env.$('lcases').innerHTML.includes('value="1"'));
  F['/api/ledger'] = {claims: [], assessment: {}, report: 'تقرير الدفتر والتقييم', chain_ok: true};
  await click(env, 'lshow'); ok('ledger: the ledger report is shown with the chain status', env.$('info').innerHTML.includes('تقرير الدفتر والتقييم') && env.$('info').innerHTML.includes('سليمة'));
  F['/api/ledger'] = {claims: [], assessment: {}, report: 'x', chain_ok: false}; await click(env, 'lshow'); ok('ledger: a damaged chain is flagged in red', env.$('info').innerHTML.includes('تالفة'));
  env.$('lcase').value = ''; env.$('info').innerHTML = ''; await click(env, 'lshow'); ok('ledger: an empty case id is refused politely', env.$('info').innerHTML.includes('اكتب رقم القضية'));
  F['/api/ledger/verify'] = {ok: true, problems: [], head: 'a'.repeat(64)}; await click(env, 'lverify'); ok('ledger: verification shows the head hash to store elsewhere', env.$('info').innerHTML.includes('a'.repeat(64)));
  F['/api/ledger/verify'] = {ok: false, problems: ['الادعاء 1: عُدِّل'], head: 'b'}; await click(env, 'lverify'); ok('ledger: a tampered ledger shows the problem', env.$('info').innerHTML.includes('عُدِّل'));
  env.$('lcase').value = '1'; env.$('lkind').value = 'platform_registration'; env.$('lsubj').value = 'Exchange X'; env.$('lcountry').value = 'MT'; env.$('lsource').value = 'Registry extract';
  env.$('lstype').value = 'company_disclosure'; env.$('ldate').value = '2026-09-30'; env.$('lmethod').value = 'official extract'; env.$('lvpn').checked = false; F['/api/ledger/add'] = {id: 1}; F['/api/ledger'] = {claims: [], assessment: {}, report: 'بعد الإضافة', chain_ok: true};
  await click(env, 'ladd'); const ac = env.calls.filter(c => c.url.startsWith('/api/ledger/add')).pop(); const ab = JSON.parse(ac.opts.body);
  ok('ledger: a claim is POSTed with source, date, method and country, then the ledger is reloaded', ab.case === '1' && ab.country === 'MT' && ab.source_type === 'company_disclosure' && ab.date === '2026-09-30' && env.$('info').innerHTML.includes('بعد الإضافة'));

  F['/api/ledger/platforms'] = {platforms: [{platform: 'Demo Exchange', registration: [{country: 'MT', strength: 'strong', entities: ['Demo Exchange Ltd'], stale: false}], channels: [{value: 'legal@demo.example', source: 'Official legal page', obtained_at: '2026-09-30', stale: true}]}, {platform: 'Other', registration: [], channels: []}]};
  await click(env, 'lplat'); const ph = env.$('info').innerHTML;
  ok('registry: the platforms table shows entity, country strength, channel with source/date, stale warning and gaps', ['Demo Exchange Ltd', 'MT', 'قوي', 'legal@demo.example', 'Official legal page', 'قديمة', 'تسجيل: غير موثّق', 'قناة الطلبات: غير مسجّلة'].every(s => ph.includes(s)));
  F['/api/ledger/platforms'] = {platforms: []}; await click(env, 'lplat'); ok('registry: an empty registry explains what to add', env.$('info').innerHTML.includes('GLOBAL'));
  F['/api/brief'] = {report: 'ملف للجهات المختصة: القضية 1', saved: 'cases/1/law_enforcement_brief.md'};
  env.$('lcase').value = '1'; await click(env, 'lbrief'); ok('brief: the law-enforcement brief is shown with its saved path', env.$('info').innerHTML.includes('ملف للجهات المختصة') && env.$('info').innerHTML.includes('cases/1/law_enforcement_brief.md'));
  env.$('lcase').value = ''; env.$('info').innerHTML = ''; await click(env, 'lbrief'); ok('brief: an empty case id is refused politely', env.$('info').innerHTML.includes('اكتب رقم القضية'));
  env.$('lcase').value = '1'; env.$('lkind').value = 'platform_channel'; env.$('lvalue').value = 'legal@demo.example'; env.$('lsubj').value = 'Demo Exchange'; await click(env, 'ladd');
  const lc2 = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/ledger/add')).pop().opts.body); ok('registry: the legal entity / channel value is sent with the claim', lc2.value === 'legal@demo.example' && lc2.kind === 'platform_channel');

  F['/api/identify'] = {report: 'هوية العنوان والأدلة: Demo Exchange', result: {}};
  env.$('wchain').value = 'btc'; env.$('waddr').value = ''; env.$('info').innerHTML = ''; await click(env, 'wid');
  ok('identity: an empty address is refused politely', env.$('info').innerHTML.includes('أدخل عنوان'));
  env.$('waddr').value = '1ABC'; env.$('wlive').checked = true; env.$('wext').checked = false; await click(env, 'wid');
  const ic = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/identify')).pop().opts.body);
  ok('identity: the address, network, live/external options and the current graph are POSTed and the report shown',
     ic.chain === 'btc' && ic.address === '1ABC' && ic.live === true && ic.external === false && ic.graph.start === 'S' && env.$('info').innerHTML.includes('Demo Exchange'));
  F['/api/links'] = {links: [], report: 'الروابط بين المحافظ: لا روابط'}; env.$('waddr').value = '';
  await click(env, 'wln'); const lcl = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/links')).pop().opts.body);
  ok('links: the current graph is POSTed (no focus when the address box is empty) and the report shown', lcl.graph.start === 'S' && lcl.address === null && env.$('info').innerHTML.includes('الروابط بين المحافظ'));
  env.$('waddr').value = '1ABC'; await click(env, 'wln'); ok('links: a typed address becomes the focus', JSON.parse(env.calls.filter(c => c.url.startsWith('/api/links')).pop().opts.body).address === '1ABC');

  F['/api/review/queue'] = {items: [{address: '1ADDR', chain: 'btc', url: 'https://x/1ADDR', reasons_ar: ['نشاط مرتفع جدًا'], inflow: 5, cases: ['c1'], proposed_label: 'Guess', proposed_category: 'exchange'}], stats: {pending: 1, confirmed: 0, rejected: 0}};
  await click(env, 'rv_load');
  ok('review: the queue card shows the address, reasons, explorer link and the proposed name', ['1ADDR', 'نشاط مرتفع جدًا', 'https://x/1ADDR', 'Guess'].every(s => env.$('info').innerHTML.includes(s)));
  env.$('rvwho').value = ''; await env.$('rvok').onclick(); await tick();
  ok('review: a decision without the reviewer name is refused on the page and nothing is sent', env.$('info').innerHTML.includes('اكتب اسمك') && !env.calls.some(c => c.url.startsWith('/api/review/decide')));
  env.$('rvwho').value = 'Sami'; env.$('rvname').value = 'Guess'; env.$('rvcat').value = 'exchange'; env.$('rvconf').value = 'medium'; env.$('rvev').value = ''; env.$('rvnote').value = '';
  F['/api/review/decide'] = {status: 'confirmed', address: '1ADDR', remaining: 0}; await env.$('rvok').onclick(); await tick();
  const rd = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/review/decide')).pop().opts.body);
  ok('review: confirming sends reviewer, label, category and confidence, then the list ends', rd.action === 'confirm' && rd.reviewer === 'Sami' && rd.label === 'Guess' && rd.category === 'exchange' && rd.confidence === 'medium' && env.$('info').innerHTML.includes('انتهت قائمة المراجعة'));
  F['/api/review/decide'] = {error: 'الثقة العالية تتطلب دليلًا مكتوبًا'}; await click(env, 'rv_load'); env.$('rvwho').value = 'Sami'; env.$('rvconf').value = 'high'; await env.$('rvok').onclick(); await tick();
  ok('review: a server refusal (high confidence without evidence) is shown on the same card', env.$('info').innerHTML.includes('الثقة العالية تتطلب دليلًا') && env.$('info').innerHTML.includes('1ADDR'));
  F['/api/review/enqueue'] = {added: 2, updated: 1}; env.$('lcase').value = 'c1'; await click(env, 'rv_enq'); const eq = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/review/enqueue')).pop().opts.body);
  ok('review: the current map and case id are sent to the queue', eq.graph.start === 'S' && eq.case === 'c1' && env.$('info').innerHTML.includes('أُضيف'));
  F['/api/review/stats'] = {pending: 3, confirmed: 2, rejected: 1, skipped: 0, decisions: 6, history_ok: false}; await click(env, 'rv_stats'); ok('review: a damaged decision history is flagged', env.$('info').innerHTML.includes('سجل القرارات تالف'));
  F['/api/review/import-official'] = {addresses: 3, added: 3, updated: 0}; env.$('of_name').value = 'Demo Exchange'; env.$('of_cat').value = 'exchange'; env.$('of_url').value = 'https://demo.example/proof'; env.$('of_date').value = '2026-09-30'; env.$('of_text').value = '1A 1B 1C'; await click(env, 'of_go');
  const oc = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/review/import-official')).pop().opts.body);
  ok('review: an official list is sent with platform, category, source link, date, reviewer and addresses', oc.platform === 'Demo Exchange' && oc.source_url === 'https://demo.example/proof' && oc.date === '2026-09-30' && oc.reviewer === 'Sami' && oc.text === '1A 1B 1C' && env.$('info').innerHTML.includes('استُورد'));
  F['/api/review/bundle'] = {bundle: {count: 5, sha256: 'f'.repeat(64)}}; await click(env, 'bd_export'); ok('review: the bundle export shows the SHA-256 to keep elsewhere', env.$('info').innerHTML.includes('f'.repeat(64)));
  F['/api/review/bundle-import'] = {added: 1, updated: 0, skipped: 2}; await env.$('bd_file').onchange({target: {files: [{name: 'b.json', text: async () => JSON.stringify({format: 'labels-bundle-1', labels: {}})}]}}); await tick();
  const bc = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/review/bundle-import')).pop().opts.body);
  ok('review: an imported bundle is sent with its name and the reviewer, and the capped result is shown', bc.name === 'b.json' && bc.reviewer === 'Sami' && env.$('info').innerHTML.includes('تُخطّي'));

  F['/api/precheck'] = {report: 'فحص قبل الدفع: تقرير', result: {verdict: 'CAUTION', verdict_ar: 'حذر: تحقق قبل أن تدفع'}};
  env.$('pc_chain').value = 'btc'; env.$('pc_addr').value = '1PAY'; env.$('pc_url').value = 'https://site.example'; env.$('pc_live').checked = true; env.$('pc_urgency').checked = true;
  await click(env, 'pc_go'); const pcb = JSON.parse(env.calls.filter(c => c.url.startsWith('/api/precheck')).pop().opts.body);
  ok('precheck (local): flags, address, link, network and the live option are POSTed, and the verdict is shown in the caution colour',
     pcb.chain === 'btc' && pcb.address === '1PAY' && pcb.url === 'https://site.example' && pcb.live === true && pcb.flags.includes('urgency') && env.$('info').innerHTML.includes('حذر') && env.$('info').innerHTML.includes('var(--busy)'));
  F['/api/precheck'] = {report: 'x', result: {verdict: 'STOP', verdict_ar: 'توقف: لا تدفع الآن'}}; await click(env, 'pc_go'); ok('precheck (local): STOP is shown in the risk colour', env.$('info').innerHTML.includes('var(--risk)'));
  F['/api/precheck'] = {error: 'عنوان غير صالح'}; await click(env, 'pc_go'); ok('precheck (local): a server refusal is shown, not swallowed', env.$('info').innerHTML.includes('عنوان غير صالح'));
  env.$('pc_urgency').checked = false; env.$('pc_addr').value = ''; env.$('pc_url').value = ''; env.$('info').innerHTML = ''; await env.$('pc_go').onclick(); await tick(); ok('precheck: an empty form is refused politely', env.$('info').innerHTML.includes('علّم ما ينطبق'));

  env.$('wt_chain').value = 'btc'; env.$('wt_addr').value = '1ABC'; env.$('wt_topic').value = 'secret'; env.$('wt_cmd').onclick();
  ok('watch: the watch command is generated (escaped, with the ntfy topic)', env.$('info').innerHTML.includes('python watch.py btc 1ABC --ntfy secret'));
  F['/api/balance'] = {balance: {BTC: 0.5}, pending: ['PENDING x']}; await click(env, 'wt_now'); ok('watch: balance and pending spends are shown', env.$('info').innerHTML.includes('PENDING x'));

  env.ev('select(nodes[1])'); const h = env.$('info').innerHTML;
  ok('map: selecting a node shows label, taint, inference note and the action buttons', h.includes('Demo Exchange') && h.includes('0.5000') && h.includes('استنتاج') && h.includes('id="tf2"'));
  ok('map: the node panel offers the identity button', h.includes('id="idn"'));
  const before = env.calls.filter(c => c.url.startsWith('/api/identify')).length; await env.$('idn').onclick(); await tick();
  ok('map: the node identity button asks for that node\'s evidence', env.calls.filter(c => c.url.startsWith('/api/identify')).length === before + 1 && JSON.parse(env.calls.filter(c => c.url.startsWith('/api/identify')).pop().opts.body).address === 'A');
  ok('map: the node panel offers the platform-or-collection diagnosis', h.includes('id="dg2"'));
  F['/api/diagnose'] = {diagnosis: {}, lines: ['الحكم: يشبه محفظة منصة/خدمة']}; await env.$('dg2').onclick(); await tick();
  ok('diagnose: the node button asks for that node and shows the explained result', env.calls.filter(c => c.url.startsWith('/api/diagnose')).pop().url.includes('address=A') && env.$('info').innerHTML.includes('يشبه محفظة منصة'));
  env.$('waddr').value = '1BUSY'; await click(env, 'wdg'); ok('diagnose: the wallet-tab button works', env.calls.filter(c => c.url.startsWith('/api/diagnose')).pop().url.includes('address=1BUSY'));
  F['/api/payments'] = {chain: 'btc', address: '1SCAM', count: 2, warning: 'العنوان مزدحم', payments: [{txid: 'c'.repeat(64), vout: 1, amount: 0.6, asset: 'BTC', time_str: '2019-03-14', rank: 3, amount_match: true, date_match: true}, {txid: 'd'.repeat(64), vout: 0, amount: 9, asset: 'BTC', time_str: '2020-01-01', rank: 0, amount_match: false, date_match: false}]};
  env.$('pchain').value = 'btc'; env.$('paddr').value = '1SCAM'; env.$('pamt').value = '0.6'; env.$('pdate').value = '2019-03-14'; await click(env, 'pk');
  const pq = env.calls.filter(c => c.url.startsWith('/api/payments')).pop().url;
  ok('payments: address, amount and date are sent and the list shows the match and the busy-address warning', pq.includes('address=1SCAM') && pq.includes('amount=0.6') && pq.includes('date=2019-03-14') && env.$('info').innerHTML.includes('يطابق المبلغ') && env.$('info').innerHTML.includes('مزدحم'));
  F['/api/case'] = {graph: GRAPH, summary: 'تقرير', letters: {}, folder: 'cases/2'}; await env.$('info').querySelectorAll('.pp')[0].onclick(); await tick(); await tick();
  const cq = env.calls.filter(c => c.url.startsWith('/api/case')).pop().url;
  ok('payments: choosing "this is my payment" builds the case from that exact output', cq.includes('txid=' + 'c'.repeat(64)) && cq.includes('vout=1') && cq.includes('stolen=0.6') && cq.includes('depth=6'));
  env.$('paddr').value = ''; await env.$('pk').onclick(); await tick(); ok('payments: an empty address is refused politely', env.$('info').innerHTML.includes('اكتب عنوان المحتال'));
  // ----- public (paid) mode
  {
    const pe = makeEnv(true, true); await tick(); await tick(); const PF = pe.fixtures;
    ok('public mode: the page marks itself public and says what is free', pe.$('body') !== undefined && pe.ctx.document.body._cls.has('pub') && pe.$('mode').textContent.includes('مجانًا'));
    PF['/api/case'] = {error: 'هذه الخدمة مدفوعة', pay: true}; PF['/api/config'] = {price: '60$', selling: true};
    pe.$('addr').value = '1ABC'; pe.$('chain').value = 'btc'; await click(pe, 'cs'); await tick();
    const hh = pe.$('info').innerHTML;
    ok('public mode: a paid step shows the price, what is included, the not-a-recovery-service line and the terms link', hh.includes('60$') && hh.includes('وليست خدمة استرداد') && hh.includes('/terms') && hh.includes('id="buy"'));
    PF['/api/order/new'] = {code: 'TR-AAAA-BBBB-CCCC', checkout_url: 'https://pay.example/x?checkout[custom][code]=TR-AAAA-BBBB-CCCC', price: '60$'};
    PF['/api/order/status'] = {status: 'paid'}; PF['/api/case'] = {graph: GRAPH, summary: 'تقرير مدفوع', letters: {}, folder: ''};
    await pe.$('buy').onclick(); await tick(); await tick(); await tick();
    const last = pe.calls.filter(c => c.url.startsWith('/api/case')).pop();
    ok('public mode: after payment the step is retried with the order code in the X-Order header and the result is shown', last.opts.headers['X-Order'] === 'TR-AAAA-BBBB-CCCC' && pe.$('info').innerHTML.includes('تقرير مدفوع'));
    pe.$('ordcode').value = ' tr-zzzz-zzzz-zzzz '; PF['/api/order/status'] = {status: 'refunded'}; await pe.$('ordgo').onclick(); await tick();
    ok('public mode: entering a refunded or unknown code is refused clearly', pe.$('info').innerHTML.includes('غير صالح') && pe.calls.filter(c => c.url.startsWith('/api/order/status')).pop().url.includes('TR-ZZZZ-ZZZZ-ZZZZ'));
  }
  F['/api/case'] = {error: 'عنوان غير صالح'}; env.$('addr').value = 'bad'; await click(env, 'cs'); ok('errors: a server error is shown to the user, not swallowed', env.$('info').innerHTML.includes('عنوان غير صالح'));
  env.$('info').innerHTML = ''; env.$('addr').value = '<img src=x onerror=alert(1)>'; F['/api/trace'] = {error: '<script>alert(1)</script>'}; await click(env, 'go');
  ok('security: server text is escaped before being shown', !env.$('info').innerHTML.includes('<script>') && env.$('info').innerHTML.includes('&lt;script&gt;'));
  // ----- networks and languages
  env = makeEnv(false); await tick();
  ok('networks: eleven networks are offered in every chain selector', env.ev('CH.length') === 11 && /<option/.test(env.$('chain').innerHTML) && (env.$('chain').innerHTML.match(/<option/g) || []).length === 11);
  ok('networks: only the untested ones are marked experimental (BTC/ETH/TRON are not)', !/value="btc">[^<]*تجريبية/.test(env.$('pchain').innerHTML) && /value="sol">Solana \(تجريبية\)/.test(env.$('pchain').innerHTML) && !/value="tron">[^<]*تجريبية/.test(env.$('pc_chain').innerHTML));
  ok('networks: Litecoin/Dogecoin/Bitcoin Cash use the UTXO depth, Ethereum/Solana the account depth', env.ev("isUtxo('ltc')&&isUtxo('doge')&&isUtxo('bch')&&isUtxo('btc')&&!isUtxo('eth')&&!isUtxo('sol')&&!isUtxo('bsc')"));
  ok('networks: explorer links follow the chain (BNB, Solana, Litecoin)', env.ev("chain='bsc';txUrl('ab')")==='https://bscscan.com/tx/ab' && env.ev("chain='sol';addrUrl('X')")==='https://solscan.io/account/X' && env.ev("chain='ltc';txUrl('ab')")==='https://litecoinspace.org/tx/ab');
  ok('languages: seven languages in the selector and Arabic is the default in this environment', env.ev('LANGS.length') === 7 && env.ev('LANG') === 'ar' && env.ev("document.documentElement.dir") === 'rtl');
  env.ev("setLang('en',false)");
  ok('languages: switching to English flips the page to LTR and translates strings', env.ev("document.documentElement.dir") === 'ltr' && env.ev("T('جارٍ الفحص...')") === 'Checking...' && env.ev("T('خطأ: لا تدفع')").includes('Error'));
  ok('languages: a longer phrase wins over its parts, and unknown Arabic is left alone', env.ev("T('الحكم: ضعيف')") === 'Verdict: Weak' && env.ev("T('كلمة غير معروفة')") === 'كلمة غير معروفة');
  ok('languages: Arabic words are not touched inside other words (no partial replacement)', env.ev("T('منصة')") === 'منصة');
  env.ev("setLang('fa',false)");
  ok('languages: Persian is RTL', env.ev("document.documentElement.dir") === 'rtl' && env.ev("T('خطأ')") !== 'خطأ');
  env.ev("setLang('ar',false)");
  ok('languages: back to Arabic restores RTL and the text unchanged', env.ev("document.documentElement.dir") === 'rtl' && env.ev("T('خطأ')") === 'خطأ');
  ok('languages: every API call carries the chosen language', (() => { env.ev("setLang('es',false)"); return env.ev("hdrs()['X-Lang']") === 'es'; })());
  console.log('\nSITE: ALL ' + n + ' CHECKS PASSED');
})().catch(e => { console.log(String(e.message || e)); process.exit(1); });
