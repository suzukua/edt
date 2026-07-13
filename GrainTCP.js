const CFG = {
    id: '',
    log: false,
    chunk: 64 * 1024,
    dnPack: 32 * 1024,
    dnTail: 512,
    dnQr: 4,
    upPack: 20 * 1024,
    upQMax: 16 * 1024 * 1024,
    upItemsMax: 4096,
    maxED: 8 * 1024,
    concur: 4
};
const DEF_PROXY_HOST = atob('UHJveHlJUC5DTUxpdXNzc3MubmV0');
const DEF_PROXY_PORT = 443;
const fmtErr = e => e?.message || e;
const log = (...args) => {
    CFG.log && console.log(...args);
};
const warn = (...args) => {
    CFG.log && console.warn(...args);
};
const error = (...args) => {
    console.error(...args);
};
let proxyCacheHost = '';
let proxyCacheList = null;
let proxyCacheIndex = 0;
export default {
    fetch: async (req, env) => {
        if (!CFG.id && env.xxoo && env.xxoo.get) {
            CFG.id = await env.xxoo.get();
        }
        if (CFG.id && !idB) {
            const out = new Uint8Array(16), id = CFG.id;
            for (let i = 0, p = 0, c, h; i < 16; i++) {
                c = id.charCodeAt(p++);
                c === 45 && (c = id.charCodeAt(p++));
                h = hex(c);
                c = id.charCodeAt(p++);
                c === 45 && (c = id.charCodeAt(p++));
                out[i] = h << 4 | hex(c);
            }
            idB = out;
        }
        if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
            return ws(req, env);
        }
        return new Response('Hello world!');
    }
};
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const dec = new TextDecoder();
let idB = null;
const matchID = c => {
    if (!idB) return false;
    for (let i = 0; i < 16; i++) if (c[i + 1] !== idB[i]) return false;
    return true;
};
const addr = (t, b) => t === 1 ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : t === 3 ? dec.decode(b) : `[${Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(':')}]`;
const sprout = (f, h, p, s = f.connect({ hostname: h, port: p })) => s.opened.then(() => s);
const raceSprout = (f, h, p) => {
    if (!f?.connect) return Promise.reject(new Error('connect unavailable'));
    if (CFG.concur <= 1) return sprout(f, h, p);
    const ts = Array(CFG.concur).fill().map(() => sprout(f, h, p));
    return Promise.any(ts).then(w => {
        ts.forEach(t => t.then(s => s !== w && s.close(), () => {
        }));
        return w;
    });
};
const parseAddr = (b, o, t) => {
    const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : null;
    if (l === null) return null;
    const n = o + l;
    return n > b.length ? null : { targetAddrBytes: b.subarray(o, n), dataOffset: n };
};
const pick = s => {
    const xs = s?.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
    return xs?.length ? xs[(Math.random() * xs.length) | 0] : '';
};
const proxyOf = (req, env) => {
    const url = new URL(req.url), qp = url.searchParams.get('proxyip');
    if (qp) return pick(qp);
    const m = url.pathname.toLowerCase().match(/\/(proxyip[.=]|pyip=|ip=)(.+)/);
    return pick(m ? (m[1] === 'proxyip.' ? `proxyip.${m[2]}` : m[2]) : env?.PROXYIP || '');
};
const splitHP = (s, p = DEF_PROXY_PORT) => {
    if (!s) return null;
    const x = s.trim();
    if (!x) return null;
    if (x.startsWith('[')) {
        const i = x.indexOf(']');
        if (i < 0) return [x, p];
        const h = x.slice(0, i + 1), pp = x.slice(i + 1);
        return [h, pp.startsWith(':') ? parseInt(pp.slice(1), 10) || p : p];
    }
    const i = x.lastIndexOf(':');
    return i > 0 && x.indexOf(':') === i ? [x.slice(0, i), parseInt(x.slice(i + 1), 10) || p] : [x, p];
};
const isIPv4 = s => /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(s);
const isIPv6 = s => /^\[[\da-fA-F:]+]$/.test(s) || /^[\da-fA-F]{0,4}(?::[\da-fA-F]{0,4}){2,}$/.test(s);
const isIpLiteral = s => isIPv4(s) || isIPv6(s);
const dohQuery = async (host, type) => {
    try {
        const resp = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
            headers: { 'Accept': 'application/dns-json' }
        });
        if (!resp.ok) return [];
        const data = await resp.json();
        return data?.Answer || [];
    } catch (e) {
        warn(`[FuckTCP] [proxyip解析] DoH查询失败 | host=${host} | type=${type} | 错误=${fmtErr(e)}`);
        return [];
    }
};
const resolveProxyList = async s => {
    const raw = (s || '').trim() || DEF_PROXY_HOST;
    if (proxyCacheHost === raw && proxyCacheList?.length) {
        log(`[FuckTCP] [proxyip解析] 命中缓存 | proxyip=${raw} | 候选=${proxyCacheList.map(([h, p]) => `${h}:${p}`).join(', ')}`);
        return proxyCacheList;
    }
    const hp = splitHP(raw) || [DEF_PROXY_HOST, DEF_PROXY_PORT];
    let [host, port] = hp;
    let out = [[host, port]];
    if (!isIpLiteral(host)) {
        const [aRecords, aaaaRecords] = await Promise.all([
            dohQuery(host, 'A'),
            dohQuery(host, 'AAAA')
        ]);
        const ipv4List = aRecords.filter(r => r.type === 1 && r.data).map(r => [r.data, port]);
        const ipv6List = aaaaRecords.filter(r => r.type === 28 && r.data).map(r => [`[${r.data}]`, port]);
        out = [...ipv4List, ...ipv6List];
        if (!out.length) out = [[host, port]];
    }
    const seen = new Set();
    proxyCacheList = out.filter(([h, p]) => {
        const key = `${h}:${p}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
    proxyCacheHost = raw;
    proxyCacheIndex = 0;
    log(`[FuckTCP] [proxyip解析] 完成 | proxyip=${raw} | 候选=${proxyCacheList.map(([h, p]) => `${h}:${p}`).join(', ')}`);
    return proxyCacheList;
};
const checkProxy = async (host, port) => {
    const candidate = `${host}:${port}`;
    log(`[FuckTCP] [proxyip检测] 开始检测 | candidate=${candidate}`);
    const testApi = `${atob('aHR0cHM6Ly9wci1hcGlzLmVrdC5tZS9wcm9iZQ==')}?candidate=${candidate}&timeoutMs=1000`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    try {
        const response = await fetch(testApi, {
            signal: controller.signal,
            cf: {
                cacheEverything: true,
                cacheKey: testApi,
                cacheTtlByStatus: { '200-299': 60, '400-599': 0 }
            }
        });
        const result = await response.json();
        if (!result?.ok) {
            warn(`[FuckTCP] [proxyip检测] 不可用 | candidate=${candidate}`);
            throw new Error('proxyip unavailable');
        }
        log(`[FuckTCP] [proxyip检测] 可用 | candidate=${result.candidate || candidate} `);
    } catch (e) {
        warn(`[FuckTCP] [proxyip检测] 探活异常 | prxip：${candidate} | 错误：${fmtErr(e)}`);
        throw e;
    } finally {
        clearTimeout(timer);
    }
};
const vls = c => {
    if (c.length < 24 || !matchID(c)) return null;
    let o = 19 + c[17];
    const p = (c[o] << 8) | c[o + 1];
    let t = c[o + 2];
    if (t !== 1) t += 1;
    const a = parseAddr(c, o + 3, t);
    return a ? { addrType: t, ...a, port: p } : null;
};
const mkK = (cap, cpy = 0) => {
    let q = [], h = 0, b = 0, buf = null;
    const e = () => h >= q.length;
    const trim = () => {
        if (h > 32 && h * 2 >= q.length) {
            q = q.slice(h);
            h = 0;
        }
    };
    const clear = () => {
        q = [];
        h = 0;
        b = 0;
    };
    const take = () => {
        if (e()) return null;
        const d = q[h];
        q[h++] = undefined;
        b -= d.byteLength;
        trim();
        return d;
    };
    const sow = d => {
        const n = d?.byteLength || 0;
        if (!n) return 1;
        q.push(d);
        b += n;
        return 1;
    };
    const pack = d => {
        d ||= take();
        if (!d || e()) return [d, 0];
        let n = d.byteLength, j = h;
        while (j < q.length) {
            const x = q[j], nn = n + x.byteLength;
            if (nn > cap) break;
            n = nn;
            j++;
        }
        if (j === h) return [d, 0];
        const out = buf ||= new Uint8Array(cap);
        out.set(d);
        for (let o = d.byteLength; h < j;) {
            const x = q[h];
            q[h++] = undefined;
            b -= x.byteLength;
            out.set(x, o);
            o += x.byteLength;
        }
        trim();
        const u = out.subarray(0, n);
        return [cpy ? u.slice() : u, 1];
    };
    return { e, get b() { return b; }, clear, take, sow, pack };
};
const mkQ = cap => {
    const k = mkK(cap);
    return { get empty() { return k.e(); }, clear: k.clear, sow: k.sow, bundle: d => k.pack(d) };
};
const mkDn = w => {
    const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, tail * 12), k = mkK(cap, 1);
    let tp = 0, gen = 0, qk = 0, qr = 0;
    const reap = () => {
        tp && clearTimeout(tp);
        tp = 0;
        qr = 0;
        for (;;) {
            const [u] = k.pack();
            if (!u) break;
            w.send(u);
        }
    };
    const ripen = () => {
        if (k.e() || tp) return;
        if (k.b >= cap || cap - k.b < tail) return reap();
        tp = setTimeout(() => {
            tp = 0;
            if (k.e()) return;
            if (k.b >= cap || cap - k.b < tail) return reap();
            if (qr < CFG.dnQr && (gen !== qk || k.b < low)) {
                qr++;
                qk = gen;
                return ripen();
            }
            reap();
        }, 1);
    };
    return {
        send(u) {
            let o = 0, n = u?.byteLength || 0;
            if (!n) return;
            while (o < n) {
                const m = Math.min(cap - k.b, n - o);
                if (!m) {
                    reap();
                    continue;
                }
                k.sow(o || m !== n ? u.subarray(o, o + m) : u);
                gen++;
                o += m;
                if (k.b >= cap || cap - k.b < tail) reap(); else ripen();
            }
        },
        reap
    };
};
const mill = async (rd, w, onFirst) => {
    const r = rd.getReader({ mode: 'byob' }), tx = mkDn(w);
    let buf = new ArrayBuffer(CFG.chunk), seen = 0;
    try {
        for (;;) {
            const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk));
            if (done) break;
            if (!v?.byteLength) continue;
            if (!seen) {
                seen = 1;
                try {
                    onFirst?.();
                } catch {
                }
            }
            if (v.byteLength >= (CFG.chunk >> 1)) {
                tx.reap();
                w.send(v);
                buf = new ArrayBuffer(CFG.chunk);
            } else {
                tx.send(v.slice());
                buf = v.buffer;
            }
        }
        tx.reap();
    } catch {
    } finally {
        try {
            tx.reap();
        } catch {
        }
        try {
            r.releaseLock();
        } catch {
        }
    }
    return !!seen;
};
const ws = async (req, env) => {
    const [client, server] = Object.values(new WebSocketPair());
    server.accept({ allowHalfOpen: true });
    server.binaryType = 'arraybuffer';
    const fetcher = req.fetcher;
    const proxyIP = proxyOf(req, env);
    const edStr = req.headers.get('sec-websocket-protocol');
    const ed = edStr && edStr.length <= CFG.maxED * 4 / 3 + 4 ? /** @type {*} */ (Uint8Array).fromBase64(edStr, { alphabet: 'base64url' }) : null;
    let curW = null, sock = null, closed = false, busy = false, pipeID = 0, retried = false, route = null;
    let proxyList = null;
    const uq = mkQ(CFG.upPack);
    const wither = () => {
        if (closed) return;
        closed = true;
        uq.clear();
        try {
            curW?.releaseLock();
        } catch {
        }
        try {
            sock?.close();
        } catch {
        }
        try {
            server.close();
        } catch {
        }
    };
    const sealReplay = () => {
        if (!route) return;
        route.ack = 1;
        route.parts = null;
        route.bytes = 0;
    };
    const keepReplay = d => {
        if (!route || route.ack || retried) return;
        const n = d?.byteLength || 0;
        if (!n) return;
        if (!route.parts || route.bytes + n > CFG.upQMax) {
            route.parts = null;
            route.bytes = 0;
            retried = true;
            return;
        }
        route.parts.push(d.slice());
        route.bytes += n;
    };
    const setConn = (s, w) => {
        try {
            curW?.releaseLock();
        } catch {
        }
        if (sock && sock !== s) try {
            sock.close();
        } catch {
        }
        sock = s;
        curW = w;
    };
    const openConn = async (host, port, first, mode = '直连') => {
        log(`[FuckTCP] [${mode}] 开始连接 -> ${host}:${port} | 首包段数=${Array.isArray(first) ? first.length : 1}`);
        const s = await raceSprout(fetcher, host, port), w = s.writable.getWriter();
        try {
            const xs = Array.isArray(first) ? first : [first];
            for (const x of xs) x?.byteLength && await w.write(x);
            log(`[FuckTCP] [${mode}] 连接成功 -> ${host}:${port} | 已写入=${xs.reduce((n, x) => n + (x?.byteLength || 0), 0)} bytes`);
            return { s, w };
        } catch (e) {
            warn(`[FuckTCP] [${mode}] 连接失败 -> ${host}:${port} | 错误=${fmtErr(e)}`);
            try {
                w.releaseLock();
            } catch {
            }
            try {
                s.close();
            } catch {
            }
            throw e;
        }
    };
    const retryProxy = async () => {
        if (closed || retried || !route?.parts?.length) throw new Error('proxy retry unavailable');
        retried = true;
        let err;
        if (!proxyList) {
            proxyList = await resolveProxyList(proxyIP).catch(() => [[DEF_PROXY_HOST, DEF_PROXY_PORT]]);
        }
        log(`[FuckTCP] [proxyip代理] 准备回退 | 目标=${route.host}:${route.port} | 请求proxyip=${proxyIP || '未指定'} | 候选数=${proxyList.length}`);
        const startIdx = proxyCacheHost === ((proxyIP || '').trim() || DEF_PROXY_HOST) ? proxyCacheIndex : 0;
        const order = [...Array(proxyList.length).keys()];
        if (startIdx > 0 && startIdx < order.length) order.unshift(...order.splice(startIdx, 1));
        for (const i of order) {
            const [host, port] = proxyList[i];
            try {
                await checkProxy(host, port);
                const { s, w } = await openConn(host, port, route.parts, `proxyip代理 ${i + 1}/${proxyList.length}`);
                setConn(s, w);
                sealReplay();
                proxyCacheIndex = i;
                log(`[FuckTCP] [proxyip代理] 已接管链路 | 目标=${route.host}:${route.port} | 出口=${host}:${port}`);
                runPipe(s, false);
                return;
            } catch (e) {
                err = e;
            }
        }
        proxyCacheList = null;
        proxyCacheHost = '';
        proxyCacheIndex = 0;
        warn(`[FuckTCP] [proxyip兜底] 候选全部失败，直连兜底 | ${DEF_PROXY_HOST}:${DEF_PROXY_PORT}`);
        try {
            const { s, w } = await openConn(DEF_PROXY_HOST, DEF_PROXY_PORT, route.parts, 'proxyip兜底');
            setConn(s, w);
            sealReplay();
            runPipe(s, false);
        } catch (e) {
            error(`[FuckTCP] [proxyip兜底] 兜底连接失败 | 目标=${route.host}:${route.port} | 错误=${fmtErr(err || e)}`);
            throw err || e;
        }
    };
    const runPipe = (s, canRetry) => {
        const id = ++pipeID;
        mill(s.readable, server, () => {
            if (!closed && id === pipeID && canRetry) sealReplay();
        }).then(seen => {
            if (closed || id !== pipeID) return;
            if (!seen && canRetry) {
                warn(`[FuckTCP] [直连] 无回包，切换到 proxyip 代理 | 目标=${route?.host}:${route?.port}`);
                return retryProxy().catch(e => {
                    error(`[FuckTCP] [proxyip代理] 回退失败 | 目标=${route?.host}:${route?.port} | 错误=${fmtErr(e)}`);
                    wither();
                });
            }
            wither();
        }, () => wither());
    };
    const toU8 = d => d instanceof Uint8Array ? d : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : new Uint8Array(d);
    const sow = d => {
        const u = toU8(d), n = u.byteLength;
        if (!n) return 1;
        if (uq.sow(u)) return 1;
        wither();
        return 0;
    };
    const sendAck = version => {
        const resp = new Uint8Array(2);
        resp[0] = version;
        server.send(resp);
    };
    const thresh = async () => {
        if (busy || closed) return;
        busy = true;
        try {
            for (;;) {
                if (closed) break;
                if (!sock) {
                    const [d] = uq.bundle();
                    if (!d) break;
                    const r = vls(d);
                    if (!r) {
                        warn('[FuckTCP] 首包解析失败或ID不匹配，连接已关闭');
                        wither();
                        return;
                    }
                    sendAck(d[0]);
                    const host = addr(r.addrType, r.targetAddrBytes), port = r.port, payload = d.subarray(r.dataOffset), [first] = uq.bundle(payload);
                    const seed = (first || payload).slice();
                    route = { host, port, parts: [seed], bytes: seed.byteLength, ack: 0 };
                    log(`[FuckTCP] 解析目标成功 | 目标=${host}:${port} | 首包=${seed.byteLength} bytes | 直连优先=${!proxyIP}`);
                    try {
                        const { s, w } = await openConn(host, port, route.parts, '直连');
                        setConn(s, w);
                        log(`[FuckTCP] [直连] 已接入链路 | 目标=${host}:${port}`);
                        runPipe(s, true);
                    } catch (e) {
                        warn(`[FuckTCP] [直连] 建链失败，切换到 proxyip 代理 | 目标=${host}:${port} | 错误=${fmtErr(e)}`);
                        await retryProxy();
                    }
                    continue;
                }
                const [d] = uq.bundle();
                if (!d) break;
                keepReplay(d);
                await curW.write(d);
            }
        } catch (e) {
            error(`[FuckTCP] [转发] 上行处理异常 | 错误=${fmtErr(e)}`);
            wither();
        } finally {
            busy = false;
            !uq.empty && !closed && thresh();
        }
    };
    if (ed && sow(ed)) thresh();
    server.addEventListener('message', e => {
        closed || (sow(e.data) && thresh());
    });
    server.addEventListener('close', () => wither());
    server.addEventListener('error', () => wither());
    return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Extensions': '' } });
};
