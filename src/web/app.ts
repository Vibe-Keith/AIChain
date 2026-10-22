/** Web miner UI: spawns mining threads, aggregates stats, shows pool earnings. */
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const poolIn = $<HTMLInputElement>('pool'), seedIn = $<HTMLInputElement>('seed'), threadsIn = $<HTMLInputElement>('threads');
const btn = $<HTMLButtonElement>('toggle'), chart = $<HTMLCanvasElement>('chart');

const store = { get: (k: string) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } } };
poolIn.value = store.get('pool') ?? location.origin;
seedIn.value = store.get('seed') ?? `browser-${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;
threadsIn.value = String(Math.max(1, Math.min(8, Math.floor((navigator.hardwareConcurrency || 2) / 2))));

let workers: Worker[] = [];
let address = '';
const totals = { shares: 0, accepted: 0, blocks: 0 };
const history: { rate: number; shares: number }[] = [];
let secRate = 0, secShares = 0, reports = 0;

function log(msg: string) {
  const li = document.createElement('li');
  li.textContent = `${new Date().toLocaleTimeString()}  ${msg}`;
  const ul = $('log'); ul.prepend(li);
  while (ul.children.length > 30) ul.lastChild!.remove();
}
const setText = (id: string, v: string | number) => { $(id).textContent = typeof v === 'number' ? v.toLocaleString() : v; };

function start() {
  store.set('pool', poolIn.value); store.set('seed', seedIn.value);
  const n = Math.max(1, Math.min(32, Number(threadsIn.value) || 1));
  for (let i = 0; i < n; i++) {
    const w = new Worker('miner.worker.js', { type: 'module' });
    w.onmessage = (e) => onMsg(e.data);
    w.postMessage({ type: 'start', poolUrl: poolIn.value.replace(/\/$/, ''), seed: seedIn.value });
    workers.push(w);
  }
  btn.textContent = 'Stop mining'; btn.dataset.on = '1';
  [poolIn, seedIn, threadsIn].forEach((x) => (x.disabled = true));
  log(`started ${n} thread${n > 1 ? 's' : ''}`);
}
function stop() {
  workers.forEach((w) => w.terminate()); workers = [];
  btn.textContent = 'Start mining'; delete btn.dataset.on;
  [poolIn, seedIn, threadsIn].forEach((x) => (x.disabled = false));
  setText('status', 'stopped'); log('stopped');
}
btn.onclick = () => (workers.length ? stop() : start());

function onMsg(m: any) {
  if (m.type === 'ready') { address = m.address; setText('address', m.address); setText('model', m.modelId); }
  else if (m.type === 'status') setText('status', m.status);
  else if (m.type === 'block') { log(`found block ${m.hash.slice(0, 12)}`); }
  else if (m.type === 'stats') {
    secRate += m.steps; secShares += m.shares;
    totals.shares += m.shares; totals.accepted += m.accepted; totals.blocks += m.blocks;
    if (++reports >= workers.length) { // one sample per second across threads
      history.push({ rate: secRate, shares: secShares }); if (history.length > 90) history.shift();
      setText('rate', secRate); setText('shares', totals.accepted); setText('blocks', totals.blocks);
      secRate = 0; secShares = 0; reports = 0; draw();
    }
  }
}

async function pollEarnings() {
  if (!address) return;
  try {
    const s = await (await fetch(poolIn.value.replace(/\/$/, '') + '/stats')).json();
    const me = s.workers?.[address.slice(0, 12)];
    setText('owed', me?.owed ?? 0); setText('paid', me?.paid ?? 0);
  } catch { /* pool down */ }
}
setInterval(pollEarnings, 5000);

function draw() {
  const dpr = devicePixelRatio || 1, w = chart.clientWidth, h = chart.clientHeight;
  chart.width = w * dpr; chart.height = h * dpr;
  const c = chart.getContext('2d')!; c.scale(dpr, dpr);
  const css = getComputedStyle(document.documentElement);
  const max = Math.max(1, ...history.map((x) => x.rate));
  const bw = w / 90;
  history.forEach((x, i) => {
    const bh = (x.rate / max) * (h - 14);
    c.fillStyle = css.getPropertyValue('--bar');
    c.fillRect(i * bw, h - bh, Math.max(1, bw - 1.5), bh);
    if (x.shares) { c.fillStyle = css.getPropertyValue('--hit'); c.beginPath(); c.arc(i * bw + bw / 2, h - bh - 6, 3, 0, 7); c.fill(); }
  });
}
addEventListener('resize', draw);
