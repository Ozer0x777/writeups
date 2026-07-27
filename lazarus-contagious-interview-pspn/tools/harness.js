'use strict';
/*
 * Safe emulation harness for the obfuscated payload found in
 * pspn-main/server/controllers/userController.js (line 8).
 *
 * Strategy: let the malware's OWN decode/control-flow logic run (so we don't
 * have to hand-reimplement its RC4/base64 string table by hand), while making
 * it IMPOSSIBLE for it to touch the real filesystem, spawn real processes, or
 * reach the real network. Any call chain we didn't anticipate falls through
 * to a "blackhole" proxy: callable, property-accessible, always logs, never
 * throws -- so unknown obfuscated call chains degrade to logged no-ops
 * instead of silently dying in the payload's own catch(e){}.
 *
 * No real requests are made. No real files are written. No real process is spawned.
 */
const vm = require('vm');
const path = require('path');
const os = require('os');
const fs = require('fs');
const util = require('util');
const crypto = require('crypto');

const LOG = [];
function log(kind, data) {
  LOG.push({ kind, data, t: Date.now() });
  console.log(`[EMU:${kind}]`, JSON.stringify(data, safeJson).slice(0, 2000));
}
function safeJson(k, v) {
  if (Buffer.isBuffer(v)) return `<Buffer len=${v.length} hex=${v.toString('hex').slice(0, 80)}>`;
  if (typeof v === 'function') return `<function ${v.name || 'anonymous'}>`;
  return v;
}

// ---- blackhole: callable + proxyable, logs everything, never throws ----
function makeBlackhole(name) {
  const fn = function (...args) {
    log('BLACKHOLE.call:' + name, { args: args.map(a => (typeof a === 'function' ? '<fn>' : a)) });
    return makeBlackhole(name + '()');
  };
  return new Proxy(fn, {
    get(t, p) {
      if (p === Symbol.toPrimitive || p === 'then' || p === 'catch' || p === 'finally') return undefined;
      if (typeof p === 'symbol') return undefined;
      return makeBlackhole(name + '.' + String(p));
    },
    apply(t, thisArg, args) {
      log('BLACKHOLE.call:' + name, { args: args.map(a => (typeof a === 'function' ? '<fn>' : a)) });
      return makeBlackhole(name + '()');
    },
  });
}

// ---- fake fs (known-safe methods explicit, everything else -> blackhole) ----
const fakeFs = new Proxy({
  writeFileSync(p, content, opts) {
    log('fs.writeFileSync', { path: p, content: String(content), contentLength: content ? content.length : 0, opts });
  },
  writeFile(p, content, opts, cb) {
    log('fs.writeFile', { path: p, content: String(content), opts });
    if (typeof opts === 'function') cb = opts;
    if (cb) setImmediate(() => cb(null));
  },
  readFileSync(p, opts) { log('fs.readFileSync', { path: p, opts }); return Buffer.from(''); },
  existsSync(p) { log('fs.existsSync', { path: p }); return false; },
  mkdirSync(p, opts) { log('fs.mkdirSync', { path: p, opts }); },
  unlinkSync(p) { log('fs.unlinkSync', { path: p }); },
  appendFileSync(p, content, opts) { log('fs.appendFileSync', { path: p, len: content ? content.length : 0, opts }); },
  chmodSync(p, mode) { log('fs.chmodSync', { path: p, mode }); },
}, {
  get(t, p) { return (p in t) ? t[p] : makeBlackhole('fs.' + String(p)); }
});

// ---- fake child_process ----
const fakeChildProcess = new Proxy({
  exec(cmd, opts, cb) {
    log('child_process.exec', { cmd, opts });
    if (typeof opts === 'function') cb = opts;
    if (cb) setImmediate(() => cb(null, '', ''));
    return { on() {}, pid: -1 };
  },
  execSync(cmd, opts) { log('child_process.execSync', { cmd, opts }); return Buffer.from(''); },
  execFile(file, args, opts, cb) {
    log('child_process.execFile', { file, args, opts });
    if (typeof args === 'function') cb = args;
    else if (typeof opts === 'function') cb = opts;
    if (cb) setImmediate(() => cb(null, '', ''));
    return { on() {}, pid: -1 };
  },
  spawn(cmd, args, opts) {
    log('child_process.spawn', { cmd, args, opts });
    const { EventEmitter } = require('events');
    const ee = new EventEmitter();
    ee.stdout = new EventEmitter();
    ee.stderr = new EventEmitter();
    setImmediate(() => ee.emit('close', 0));
    return ee;
  },
}, {
  get(t, p) { return (p in t) ? t[p] : makeBlackhole('child_process.' + String(p)); }
});

// ---- fake network ----
function fakeRequest(url, opts) {
  log('NETWORK.request', { url, opts });
  // No real network access. To observe the *shape* of the post-fetch logic
  // (decrypt/write/exec) without ever hitting the real C2, hand back a
  // syntactically-plausible dummy body (iv_hex:ciphertext_hex) instead of
  // rejecting outright. Any crypto failure downstream is expected and safe
  // (it's still fully sandboxed fs/exec).
  const fakeData = '00112233445566778899aabbccddeeff'.slice(0, 32) + ':deadbeef00112233';
  return Promise.resolve({ data: fakeData, status: 200, headers: {} });
}
const fakeAxios = new Proxy(fakeRequest, {
  get(t, p) {
    if (['get', 'post', 'put', 'delete', 'patch', 'request'].includes(p)) return (url, opts) => fakeRequest(url, opts);
    if (p === 'default' || p === 'create') return p === 'create' ? (cfg) => { log('NETWORK.axios.create', { cfg }); return fakeAxios; } : fakeAxios;
    return makeBlackhole('axios.' + String(p));
  },
  apply(t, thisArg, args) { return fakeRequest(...args); }
});
const httpLike = new Proxy({
  get(url, opts, cb) { log('NETWORK.http.get', { url, opts }); return { on() {}, end() {} }; },
  request(url, opts, cb) { log('NETWORK.http.request', { url, opts }); return { on() {}, end() {}, write() {} }; },
}, { get(t, p) { return (p in t) ? t[p] : makeBlackhole('http.' + String(p)); } });

const requiredModules = new Set();
function fakeRequire(name) {
  requiredModules.add(name);
  log('require', { module: name });
  switch (name) {
    case 'fs': return fakeFs;
    case 'os': return os;
    case 'path': return path;
    case 'crypto': return new Proxy(crypto, {
      get(t, p) {
        const orig = t[p];
        if (typeof orig !== 'function') return orig;
        return (...args) => {
          try {
            const r = orig.apply(t, args);
            log('crypto.' + String(p), { args: args.map(a => (Buffer.isBuffer(a) ? a.toString('hex') : a)), ok: true });
            return r;
          } catch (e) {
            log('crypto.' + String(p) + '.THROW', { args: args.map(a => (Buffer.isBuffer(a) ? a.toString('hex') : a)), error: e.message });
            throw e;
          }
        };
      }
    });
    case 'util': return util;
    case 'child_process': return fakeChildProcess;
    case 'axios': return fakeAxios;
    case 'node-fetch': return fakeRequest;
    case 'http': return httpLike;
    case 'https': return httpLike;
    case 'net': return { Socket: class extends require('events').EventEmitter { connect(...a) { log('net.Socket.connect', { args: a }); } write() {} } };
    case 'dotenv': return { config(o) { log('dotenv.config', { o }); return {}; } };
    default:
      log('require.UNKNOWN', { module: name });
      return makeBlackhole('require(' + name + ')');
  }
}

const sandbox = {
  require: fakeRequire,
  console,
  process: new Proxy(process, {
    get(t, p) {
      if (p === 'exit') return (code) => log('process.exit', { code });
      return t[p];
    }
  }),
  Buffer,
  setTimeout, clearTimeout, setImmediate, clearImmediate, setInterval, clearInterval,
  Promise, Symbol, Map, Set, Array, Object, String, Number, Boolean, JSON, Math, Date, RegExp,
  Error, TypeError, RangeError,
  module: { exports: {} },
  exports: {},
  __filename: '/sandbox/userController.js',
  __dirname: '/sandbox',
};
sandbox.global = sandbox;

const code = fs.readFileSync(process.argv[2], 'utf8');

vm.createContext(sandbox);
try {
  vm.runInContext(code, sandbox, { filename: 'payload.js', timeout: 15000 });
} catch (e) {
  log('SANDBOX_EXCEPTION', { message: e.message, stack: (e.stack || '').split('\n').slice(0, 6) });
}

setTimeout(() => {
  fs.writeFileSync(process.argv[3] || '/tmp/emu_log.json', JSON.stringify(LOG, safeJson, 2));
  console.log('--- done, log entries:', LOG.length, 'required modules:', [...requiredModules], '---');
}, 1500);
