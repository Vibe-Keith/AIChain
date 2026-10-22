#!/usr/bin/env python3
"""Python AIChain mining pool + browser inquiry/chat gateway.

This service is API-compatible with the bundled AIChain Node worker. It submits
browser inquiries as ordinary signed AIChain job transactions and polls the node
until a miner produces a verified answer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import struct
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import Request, urlopen

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent
BLOCK_REWARD = 50
MODEL_D, MODEL_V, MODEL_LO, MODEL_HI = 128, 256, 32, 126
FEE_PCT = 2
SHARE_MULT = 64
CHECK_RATE = 0.10
PPLNS_N = 2000
PAYOUT_MIN = 10
CONFIRMS = 3
ATTEMPTS_PER_WORK = 8
MAX_PROMPT = 512
MAX_TOKENS = 128

logging.basicConfig(level=logging.INFO, format='%(asctime)s [pool.py] %(levelname)s %(message)s')
log = logging.getLogger('aichain-pool')


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _jsonable(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def canon(value: Any) -> str:
    """Match src/shared/canon.ts for AIChain's ASCII-keyed JSON structures."""
    return json.dumps(_jsonable(value), ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def sha256(*parts: bytes | str) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode('utf-8') if isinstance(part, str) else part)
    return h.hexdigest()


class Wallet:
    def __init__(self, seed: str):
        raw = hashlib.sha256(seed.encode('utf-8')).digest()
        self.key = Ed25519PrivateKey.from_private_bytes(raw)
        self.address = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def sign(self, message: str) -> str:
        return self.key.sign(message.encode('utf-8')).hex()

    def make_tx(self, body: dict[str, Any]) -> dict[str, Any]:
        tx_id = sha256(canon(body))
        return {**body, 'id': tx_id, 'sig': self.sign(tx_id)}


def verify_sig(address: str, message: str, signature: str) -> bool:
    try:
        if len(address) != 64 or len(signature) != 128:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(address)).verify(
            bytes.fromhex(signature), message.encode('utf-8'))
        return True
    except (ValueError, InvalidSignature):
        return False


def job_seed(prev_hash: str, miner: str, job_id: str, attempt: int) -> str:
    return sha256(f'{prev_hash}|{miner}|{job_id}|{attempt}')


def block_hash(block: dict[str, Any]) -> str:
    header = {k: v for k, v in block.items() if k not in ('hash', 'txs', 'results')}
    header['txRoot'] = sha256(canon(block['txs']))
    header['resRoot'] = sha256(canon(block['results']))
    return sha256(canon(header))


def _xorshift(seed: int):
    state = seed & 0xFFFFFFFF or 1
    while True:
        state = (state ^ ((state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
        state = (state ^ (state >> 17)) & 0xFFFFFFFF
        state = (state ^ ((state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
        yield state


def _make_weights():
    rng = _xorshift(0xC0FFEE)
    arrays = []
    for n in (MODEL_V * MODEL_D, MODEL_D * MODEL_D, MODEL_D * MODEL_V):
        vals = np.fromiter(((next(rng) % 16) - 8 for _ in range(n)), dtype=np.int8, count=n)
        arrays.append(vals)
    e, wh, wo = arrays
    model_id = sha256(e.tobytes(), wh.tobytes(), wo.tobytes())[:16]
    return e.reshape(MODEL_V, MODEL_D).astype(np.int32), wh.reshape(MODEL_D, MODEL_D).astype(np.int32), wo.reshape(MODEL_D, MODEL_V).astype(np.int32), model_id


_E, _WH, _WO, MODEL_ID = _make_weights()


def run_job(prompt: str, max_tokens: int, seed_hex: str, target: int, share_target: int | None = None) -> dict[str, Any]:
    """Bit-exact Python port of the prototype TinyLM model for share checks."""
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise ValueError('job seed must be 32 bytes')
    h = np.fromiter((seed[i % 32] - 128 for i in range(MODEL_D)), dtype=np.int32, count=MODEL_D)
    step_no, win = 0, -1
    shares: list[int] = []

    def step(tok: int) -> None:
        nonlocal h, step_no, win
        acc = _WH @ h + _E[tok] * 64
        h = np.clip(acc >> 6, -127, 127).astype(np.int32)
        if win < 0 or share_target is not None:
            hb = (h & 255).astype(np.uint8).tobytes()
            ticket = int(sha256(seed, str(step_no), hb), 16)
            if win < 0 and ticket < target:
                win = step_no
            if share_target is not None and ticket < share_target:
                shares.append(step_no)
        step_no += 1

    for b in prompt.encode('utf-8'):
        step(b)

    rng = _xorshift(struct.unpack('<I', seed[:4])[0])
    out = []
    for _ in range(max_tokens):
        noise = np.fromiter((next(rng) % 4096 for _ in range(MODEL_HI - MODEL_LO + 1)), dtype=np.int64)
        logits = noise + (_WO[:, MODEL_LO:MODEL_HI + 1].astype(np.int64).T @ h.astype(np.int64))
        # JS keeps the first token on ties; argmax returns the first index.
        tok = MODEL_LO + int(np.argmax(logits))
        out.append(chr(tok))
        step(tok)
    return {'output': ''.join(out), 'win': win, 'steps': step_no, 'shares': shares}


def http_json(url: str, method: str = 'GET', body: dict[str, Any] | None = None, timeout: float = 5) -> Any:
    data = None if body is None else json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    req = Request(url, data=data, method=method, headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return json.loads(raw.decode('utf-8')) if raw else {}


class PoolState:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.node_url = args.node.rstrip('/')
        self.pool_wallet = Wallet(args.seed)
        self.chat_wallet = Wallet(args.chat_seed)
        self.lock = threading.RLock()
        self.current: dict[str, Any] | None = None
        self.templates: dict[str, dict[str, Any]] = {}
        self.ranges: dict[tuple[str, str], list[tuple[int, int]]] = {}
        self.seen: set[str] = set()
        self.workers: dict[str, dict[str, Any]] = {}
        self.share_window: deque[str] = deque(maxlen=PPLNS_N)
        self.pending: list[dict[str, Any]] = []
        self.found: list[dict[str, Any]] = []
        self.requests_by_ip: dict[str, deque[float]] = {}
        self.db_path = Path(args.db).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.db:
            self.db.execute('''CREATE TABLE IF NOT EXISTS inquiries (
                id TEXT PRIMARY KEY, session_id TEXT NOT NULL, question TEXT NOT NULL,
                status TEXT NOT NULL, answer TEXT, height INTEGER, block_hash TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error TEXT
            )''')
            self.db.execute('CREATE INDEX IF NOT EXISTS inquiries_session_created ON inquiries(session_id, created_at)')
        self.chat_nonce_lock = threading.Lock()

    def worker(self, address: str) -> dict[str, Any]:
        if address not in self.workers:
            self.workers[address] = {'shares': 0, 'owed': 0, 'paid': 0, 'banned': False, 'blocks': 0}
        return self.workers[address]

    def node_get(self, path: str) -> Any:
        return http_json(self.node_url + path)

    def ban(self, addr: str, why: str) -> None:
        self.worker(addr)['banned'] = True
        self.share_window = deque((x for x in self.share_window if x != addr), maxlen=PPLNS_N)
        log.warning('BANNED %s: %s', addr[:8], why)

    def refresh_template(self) -> None:
        try:
            t = self.node_get(f'/template?miner={self.pool_wallet.address}')
            txs = t.get('txs', [])
            jobs = [x for x in txs if x.get('type') == 'job']
            with self.lock:
                if not jobs:
                    self.current = None
                    return
                work_id = sha256(t['prevHash'] + ','.join(x['id'] for x in txs))[:16]
                if self.current and self.current['workId'] == work_id:
                    return
                target = int(t['target'], 16)
                template = {
                    'workId': work_id, 'height': t['height'], 'prevHash': t['prevHash'],
                    'prevTimestamp': t['prevTimestamp'], 'target': target, 'shareTarget': target * SHARE_MULT,
                    'txs': txs, 'jobs': jobs, 'next': 0,
                }
                self.templates = {key: val for key, val in self.templates.items() if val['prevHash'] == t['prevHash']}
                self.templates[work_id] = template
                self.current = template
        except Exception as exc:
            log.debug('template refresh: %s', exc)

    @staticmethod
    def reward_for(txs: list[dict[str, Any]]) -> int:
        return BLOCK_REWARD + sum((tx['fee'] - tx['fee'] // 2) if tx['type'] == 'job' else tx['fee'] for tx in txs)

    def pplns_split(self, reward: int) -> dict[str, int]:
        if not self.share_window:
            return {}
        distributable = reward - (reward * FEE_PCT // 100)
        counts = Counter(self.share_window)
        return {addr: distributable * count // len(self.share_window) for addr, count in counts.items()}

    def handle_submit(self, sub: dict[str, Any]) -> dict[str, Any]:
        sig = sub.get('sig', '')
        body = {k: v for k, v in sub.items() if k != 'sig'}
        if not verify_sig(str(sub.get('worker', '')), sha256(canon(body)), str(sig)):
            return {'error': 'bad sig'}
        addr = str(sub['worker'])
        with self.lock:
            wk = self.worker(addr)
            if wk['banned']:
                return {'error': 'banned'}
            tp = self.templates.get(str(sub.get('workId')))
            if not tp or not self.current or tp['prevHash'] != self.current['prevHash']:
                return {'stale': True}
            start_end = self.ranges.get((str(sub['workId']), addr), [])
            attempt = int(sub['attempt'])
            if not any(start <= attempt < end for start, end in start_end):
                return {'error': 'attempt not assigned to you'}

            shares = sub.get('shares', [])
            if shares and secrets.randbelow(10_000) < int(CHECK_RATE * 10_000):
                job_id = shares[0].get('jobId')
                job = next((j for j in tp['jobs'] if j.get('id') == job_id), None)
                if not job:
                    self.ban(addr, 'unknown job')
                    return {'error': 'banned'}
                run = run_job(job['prompt'], job['maxTokens'], job_seed(tp['prevHash'], self.pool_wallet.address, job['id'], attempt), tp['target'], tp['shareTarget'])
                claimed = [s for s in shares if s.get('jobId') == job_id]
                if not all(s.get('step') in run['shares'] for s in claimed):
                    self.ban(addr, 'fake share')
                    return {'error': 'banned'}

            credited = 0
            for share in shares:
                key = f"{sub['workId']}|{attempt}|{share.get('jobId')}|{share.get('step')}"
                if key in self.seen or not any(j['id'] == share.get('jobId') for j in tp['jobs']):
                    continue
                self.seen.add(key)
                self.share_window.append(addr)
                wk['shares'] += 1
                credited += 1
            win = sub.get('win')
            if not win:
                return {'ok': True, 'credited': credited}
            idx = next((i for i, tx in enumerate(tp['txs']) if tx['id'] == win.get('jobId')), -1)
            if idx < 0:
                self.ban(addr, 'bad win job')
                return {'error': 'banned'}
            txs = tp['txs'][:idx + 1]
            block = {
                'height': tp['height'], 'prevHash': tp['prevHash'],
                'timestamp': max(int(time.time() * 1000), tp['prevTimestamp'] + 1),
                'miner': self.pool_wallet.address, 'target': format(tp['target'], 'x'), 'attempt': attempt,
                'proof': {'jobId': win['jobId'], 'step': win['step']}, 'txs': txs,
                'results': win['results'], 'hash': '',
            }
            block['hash'] = block_hash(block)

        try:
            result = http_json(self.node_url + '/block', method='POST', body=block)
        except Exception as exc:
            return {'error': f'node unavailable: {exc}'}
        with self.lock:
            if not str(result.get('result', '')).startswith('added'):
                self.ban(addr, f"invalid block ({result.get('result')})")
                return {'error': 'banned'}
            reward = self.reward_for(txs)
            self.pending.append({'hash': block['hash'], 'height': block['height'], 'split': self.pplns_split(reward)})
            self.found.append({'height': block['height'], 'hash': block['hash'], 'reward': reward})
            wk['blocks'] += 1
        log.info('BLOCK #%s found by %s, reward %s; awaiting confirmations', block['height'], addr[:8], reward)
        self.refresh_template()
        return {'ok': True, 'credited': credited, 'block': block['hash']}

    def settle(self) -> None:
        with self.lock:
            pending = list(self.pending)
        for item in pending:
            try:
                c = self.node_get(f"/confirm/{item['hash']}")
                with self.lock:
                    if item not in self.pending:
                        continue
                    if c.get('confirmations', -1) >= CONFIRMS:
                        for addr, amount in item['split'].items():
                            self.worker(addr)['owed'] += amount
                        self.pending.remove(item)
                    elif c.get('confirmations', -1) < 0 and c.get('tipHeight', 0) >= item['height'] + CONFIRMS:
                        self.pending.remove(item)
                        log.warning('block #%s orphaned; no payout', item['height'])
            except Exception:
                pass

    def payout(self) -> None:
        try:
            acct = self.node_get(f'/account/{self.pool_wallet.address}')
            nonce, balance = int(acct['pendingNonce']), int(acct['balance'])
            with self.lock:
                eligible = [(addr, dict(w)) for addr, w in self.workers.items()]
            for addr, wk in eligible:
                if wk['banned'] or wk['owed'] < PAYOUT_MIN or balance < wk['owed'] + 1:
                    continue
                tx = self.pool_wallet.make_tx({'type': 'transfer', 'from': self.pool_wallet.address, 'to': addr, 'amount': wk['owed'], 'fee': 1, 'nonce': nonce})
                try:
                    resp = http_json(self.node_url + '/tx', method='POST', body=tx)
                except Exception:
                    continue
                if not resp.get('ok'):
                    continue
                with self.lock:
                    actual = self.worker(addr)
                    if actual['owed'] == wk['owed']:
                        actual['paid'] += actual['owed']
                        actual['owed'] = 0
                    else:
                        actual['owed'] -= wk['owed']
                        actual['paid'] += wk['owed']
                log.info('paid %s to %s', wk['owed'], addr[:8])
                balance -= wk['owed'] + 1
                nonce += 1
        except Exception:
            pass

    def create_inquiry(self, question: str, session_id: str, remote_ip: str) -> dict[str, Any]:
        question = question.strip()
        if not question:
            raise ValueError('Please enter a question.')
        if len(question) > MAX_PROMPT:
            raise ValueError(f'Question must be {MAX_PROMPT} characters or fewer.')
        if len(session_id) > 128:
            raise ValueError('Invalid session id.')
        now = time.time()
        with self.lock:
            hits = self.requests_by_ip.setdefault(remote_ip, deque())
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= 6:
                raise PermissionError('Please wait a minute before sending more questions.')
            hits.append(now)
        with self.chat_nonce_lock:
            acct = self.node_get(f'/account/{self.chat_wallet.address}')
            nonce = int(acct['pendingNonce'])
            body = {'type': 'job', 'from': self.chat_wallet.address, 'prompt': question,
                    'maxTokens': self.args.chat_tokens, 'fee': self.args.chat_fee, 'nonce': nonce}
            tx = self.chat_wallet.make_tx(body)
            reply = http_json(self.node_url + '/tx', method='POST', body=tx)
        if not reply.get('ok'):
            raise RuntimeError(reply.get('error', 'The AIChain node rejected the inquiry.'))
        now_text = datetime.now(timezone.utc).isoformat()
        sid = session_id or secrets.token_urlsafe(18)
        with self.lock, self.db:
            self.db.execute('''INSERT OR REPLACE INTO inquiries
                (id,session_id,question,status,answer,height,block_hash,created_at,updated_at,error)
                VALUES(?,?,?,'pending',NULL,NULL,NULL,?,?,NULL)''',
                (tx['id'], sid, question, now_text, now_text))
        return {'id': tx['id'], 'sessionId': sid, 'question': question, 'status': 'pending', 'createdAt': now_text}

    def inquiry_status(self, inquiry_id: str) -> dict[str, Any]:
        with self.lock:
            row = self.db.execute('SELECT * FROM inquiries WHERE id=?', (inquiry_id,)).fetchone()
        if not row:
            return {'status': 'unknown', 'id': inquiry_id}
        item = dict(row)
        if item['status'] == 'pending':
            try:
                job = self.node_get('/job/' + inquiry_id)
                now_text = datetime.now(timezone.utc).isoformat()
                if job.get('status') == 'done':
                    item.update(status='done', answer=job.get('output', ''), height=job.get('height'), block_hash=job.get('block'))
                elif job.get('status') == 'unknown':
                    item.update(status='error', error='The node no longer knows this inquiry. It may not have reached the network.')
                if item['status'] != row['status']:
                    with self.lock, self.db:
                        self.db.execute('UPDATE inquiries SET status=?,answer=?,height=?,block_hash=?,updated_at=?,error=? WHERE id=?',
                            (item['status'], item.get('answer'), item.get('height'), item.get('block_hash'), now_text, item.get('error'), inquiry_id))
            except Exception:
                pass
        return {'id': item['id'], 'sessionId': item['session_id'], 'question': item['question'],
                'status': item['status'], 'answer': item.get('answer'), 'height': item.get('height'),
                'block': item.get('block_hash'), 'createdAt': item['created_at'], 'error': item.get('error')}

    def list_inquiries(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute('SELECT id FROM inquiries WHERE session_id=? ORDER BY created_at DESC LIMIT ?',
                                   (session_id, max(1, min(100, limit)))).fetchall()
        return [self.inquiry_status(row['id']) for row in reversed(rows)]

    def stats(self) -> dict[str, Any]:
        with self.lock:
            count = self.db.execute('SELECT COUNT(*) FROM inquiries').fetchone()[0]
            return {'pool': self.pool_wallet.address, 'feePct': FEE_PCT, 'window': len(self.share_window),
                    'blocksFound': len(self.found), 'pendingBlocks': len(self.pending), 'inquiries': count,
                    'workers': {addr[:12]: dict(w) for addr, w in self.workers.items()}}


class PoolHandler(BaseHTTPRequestHandler):
    server_version = 'AIChainPythonPool/1.0'
    protocol_version = 'HTTP/1.1'

    @property
    def state(self) -> PoolState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info('%s - %s', self.address_string(), fmt % args)

    def send_json(self, data: Any, code: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, Any]:
        size = int(self.headers.get('Content-Length', '0'))
        if size > 64 * 1024:
            raise ValueError('Request body too large.')
        return json.loads(self.rfile.read(size).decode('utf-8')) if size else {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path
        query = parse_qs(parsed.query)
        try:
            if route == '/work':
                worker = query.get('worker', [''])[0]
                if len(worker) != 64 or any(c not in '0123456789abcdef' for c in worker):
                    return self.send_json({'error': 'worker address required'}, 400)
                with self.state.lock:
                    current = self.state.current
                    if not current:
                        return self.send_json({'idle': True})
                    start = current['next']
                    current['next'] += ATTEMPTS_PER_WORK
                    ranges = self.state.ranges.setdefault((current['workId'], worker), [])
                    ranges.append((start, start + ATTEMPTS_PER_WORK))
                    return self.send_json({'modelId': MODEL_ID, 'workId': current['workId'], 'prevHash': current['prevHash'],
                        'miner': self.state.pool_wallet.address, 'target': format(current['target'], 'x'),
                        'shareTarget': format(current['shareTarget'], 'x'), 'jobs': current['jobs'],
                        'attemptFrom': start, 'attemptTo': start + ATTEMPTS_PER_WORK})
            if route == '/stats':
                return self.send_json(self.state.stats())
            if route == '/api/health':
                try:
                    node = self.state.node_get('/status')
                    return self.send_json({'ok': True, 'node': node, 'modelId': MODEL_ID, 'pythonPool': True})
                except Exception as exc:
                    return self.send_json({'ok': False, 'error': str(exc), 'modelId': MODEL_ID, 'pythonPool': True}, 503)
            if route == '/api/inquiries':
                sid = query.get('sessionId', [''])[0]
                return self.send_json({'items': self.state.list_inquiries(sid)})
            if route.startswith('/api/inquiries/'):
                iid = unquote(route.rsplit('/', 1)[-1])
                return self.send_json(self.state.inquiry_status(iid))
            # Web files: prefer source HTML, then built JS/WASM assets.
            relative = 'index.html' if route == '/' else unquote(route.lstrip('/'))
            if '..' not in Path(relative).parts:
                candidates = [ROOT / 'web' / relative, ROOT / 'dist' / 'web' / relative]
                file = next((p for p in candidates if p.is_file()), None)
                if file:
                    content = file.read_bytes()
                    mime = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
                            '.mjs': 'text/javascript; charset=utf-8', '.wasm': 'application/wasm',
                            '.json': 'application/json', '.css': 'text/css; charset=utf-8'}.get(file.suffix, 'application/octet-stream')
                    self.send_response(200)
                    self.send_header('Content-Type', mime)
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
            return self.send_json({'error': 'not found'}, 404)
        except Exception as exc:
            log.exception('GET %s failed', route)
            return self.send_json({'error': str(exc)}, 500)

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        try:
            body = self.read_json()
            if route == '/submit':
                return self.send_json(self.state.handle_submit(body))
            if route in ('/api/inquiries', '/inquiries'):
                question = body.get('question', body.get('prompt', ''))
                try:
                    result = self.state.create_inquiry(str(question), str(body.get('sessionId', '')), self.client_address[0])
                    return self.send_json(result, 201)
                except PermissionError as exc:
                    return self.send_json({'error': str(exc)}, 429)
                except ValueError as exc:
                    return self.send_json({'error': str(exc)}, 400)
                except Exception as exc:
                    return self.send_json({'error': str(exc)}, 502)
            return self.send_json({'error': 'not found'}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({'error': f'invalid request: {exc}'}, 400)
        except Exception as exc:
            log.exception('POST %s failed', route)
            return self.send_json({'error': str(exc)}, 500)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Python AIChain mining pool with browser inquiry chat')
    parser.add_argument('--host', default='127.0.0.1', help='bind address (default: localhost for safety)')
    parser.add_argument('--port', type=int, default=4000)
    parser.add_argument('--node', default='http://127.0.0.1:3001')
    parser.add_argument('--seed', default='pool-1', help='pool miner wallet seed')
    parser.add_argument('--chat-seed', default='devnet-faucet', help='funded wallet seed used to pay inquiry job fees')
    parser.add_argument('--chat-fee', type=int, default=2)
    parser.add_argument('--chat-tokens', type=int, default=64)
    parser.add_argument('--db', default=str(ROOT / 'data' / 'inquiries.sqlite3'))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.chat_fee < 1 or args.chat_tokens < 1 or args.chat_tokens > MAX_TOKENS:
        raise SystemExit('--chat-fee must be >= 1 and --chat-tokens must be between 1 and 128')
    state = PoolState(args)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server((args.host, args.port), PoolHandler)
    server.state = state  # type: ignore[attr-defined]
    def background() -> None:
        last_settle, last_payout = 0.0, 0.0
        while True:
            state.refresh_template()
            now = time.monotonic()
            if now - last_settle >= 5:
                state.settle(); last_settle = now
            if now - last_payout >= 10:
                state.payout(); last_payout = now
            time.sleep(1)
    threading.Thread(target=background, daemon=True, name='pool-maintenance').start()
    log.info('Python pool listening on http://%s:%s (node %s, pool %s, model %s)', args.host, args.port, args.node, state.pool_wallet.address[:12], MODEL_ID)
    log.info('Browser inquiry chat is enabled at /; inquiry job fee=%s, tokens=%s', args.chat_fee, args.chat_tokens)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        log.info('shutting down')
    finally:
        server.shutdown()
        server.server_close()
        state.db.close()


if __name__ == '__main__':
    main()
