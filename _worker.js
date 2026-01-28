import {DurableObject} from 'cloudflare:workers';
import {connect} from "cloudflare:sockets";

let 返袋IP = '';
let 缓存返袋IP, 缓存返袋解析数组, 缓存返袋数组索引 = 0;
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
    async fetch(request, env, ctx) {
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader === 'websocket'){
            let xxoo = '';
            if (env.xxoo && env.xxoo.get) {
                xxoo = await env.xxoo.get()
            }
            const stub = await getDo(env)
            if (stub) {
                return stub.fetch(request, {headers: {...Object.fromEntries(request.headers), "userid": xxoo}});
            } else {
                await 返袋参数获取(request);
                return await 处理WS请求(request, xxoo);
            }
        }
        return new Response(JSON.stringify(request.cf, null, 2), {headers: {"Content-Type": "application/json; charset=utf-8"}});
    }
};


function getDo(env){
    if (!env.WsBigDo) {
        return null;
    }
    const doLocation = env.REGION || "apac";
    const name = `user-${doLocation}`;
    const id = env.WsBigDo.idFromName(name);
    return env.WsBigDo.get(id, {locationHint: doLocation})
}

/* ------------------- Durable Object 本体 ------------------- */
export class WsBigDo extends DurableObject {

    /**
     * 构造函数
     * @param state
     * @param env
     */
    constructor(state, env) {
        super(state, env);
    }

    /**
     * @param {Request} request
     * @returns {Promise<Response>}
     */
    async fetch(request) {
        const userId = request.headers.get('userid');
        await 返袋参数获取(request);
        return await 处理WS请求(request, userId);
    }
}

///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
async function 处理WS请求(request, yourUUID) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const { port, hostname, rawIndex, version, isUDP } = 解析魏烈思请求(chunk, yourUUID);
            if (isUDP) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            const respHeader = new Uint8Array([version[0], 0]);
            const rawData = chunk.slice(rawIndex);
            if (isDnsQuery) return forwardataudp(rawData, serverSock, respHeader);
            await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID);
        },
    })).catch((err) => {
        // console.error('Readable pipe error:', err);
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}

function 解析魏烈思请求(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: `command ${cmd} is not supported, command 01-tcp,02-udp,03-mux` }; }
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    switch (addressType) {
        case 1:
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
            break;
        case 2:
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
            break;
        case 3:
            addrLen = 16;
            const ipv6 = [];
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
            hostname = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID) {
    console.log(`[TCP转发] 目标: ${host}:${portNum} | 返袋IP: ${返袋IP} | 返袋类型: pryip}`);

    async function connectPxy(address, port, data, 所有返袋数组 = null, 返袋兜底 = true) {
        let remoteSock;
        if (所有返袋数组 && 所有返袋数组.length > 0) {
            for (let i = 0; i < 所有返袋数组.length; i++) {
                const 返袋数组索引 = (缓存返袋数组索引 + i) % 所有返袋数组.length;
                const [返袋地址, 返袋端口] = 所有返袋数组[返袋数组索引];
                try {
                    console.log(`[返袋连接] 尝试连接到: ${返袋地址}:${返袋端口} (索引: ${返袋数组索引})`);
                    const pxyOk = await validPxyIp(返袋地址, 返袋端口);
                    if (!pxyOk) {
                        throw new Error('validPxyIp检查到返袋IP不可用');
                    }
                    remoteSock = connect({ hostname: 返袋地址, port: 返袋端口 });
                    // 等待TCP连接真正建立，设置1秒超时
                    await Promise.race([
                        remoteSock.opened,
                        new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), 1000))
                    ]);
                    const testWriter = remoteSock.writable.getWriter();
                    try {
                        await testWriter.write(data);
                    } finally {
                        testWriter.releaseLock(); // 无论成功失败，必须释放锁
                    }
                    console.log(`[返袋连接] 成功连接到: ${返袋地址}:${返袋端口}`);
                    缓存返袋数组索引 = 返袋数组索引;
                    return remoteSock;
                } catch (err) {
                    console.log(`[返袋连接] 连接失败: ${返袋地址}:${返袋端口}, 错误: ${err.message}`);
                    try { remoteSock?.close?.(); } catch (e) { }
                    缓存返袋解析数组.splice(返袋数组索引, 1)
                    i--; // 调整索引以避免跳过下一项
                    continue;
                }
            }
            //重试完毕所有返袋IP，说明所有IP均不可用，清空，下次请求重新解析返袋
            缓存返袋数组索引 = 0;
            缓存返袋解析数组 = null;
        }

        if (返袋兜底) {
            console.log(`[返袋兜底] 连接到: ${address}:${port}`)
            remoteSock = connect({ hostname: address, port: port });
            const writer = remoteSock.writable.getWriter();
            try {
                await writer.write(data);
            } finally {
                writer.releaseLock(); // 无论成功失败，必须释放锁
            }
            return remoteSock;
        } else {
            closeSocketQuietly(ws);
            throw new Error('[返袋连接] 所有返袋连接失败，且未启用返袋兜底，连接终止。');
        }
    }

    async function connectDirect(address, port, data) {
        let remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        try {
            await writer.write(data);
        } finally {
            writer.releaseLock(); // 无论成功失败，必须释放锁
        }
        return remoteSock;
    }

    async function connecttoPry() {
        console.log(`[返袋连接] 代理到: ${host}:${portNum}, 反代IP：${返袋IP}`);
        const 所有返袋数组 = await 解析地址端口(返袋IP, host, yourUUID);
        let newSocket = await connectPxy(atob('UHJveHlJUC5DTUxpdXNzc3MubmV0'), 443, rawData, 所有返袋数组, true);
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null, host, portNum);
    }

    try {
        console.log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
        const initialSocket = await connectDirect(host, portNum, rawData);
        console.log(`[TCP转发] 直连成功: ${host}:${portNum}`);
        remoteConnWrapper.socket = initialSocket;
        connectStreams(initialSocket, ws, respHeader, connecttoPry, host, portNum);
    } catch (err) {
        console.log(`[TCP转发] 直连失败: ${host}:${portNum}， 通过返袋重试`);
        await connecttoPry();
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let weiHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (weiHeader) {
                        const response = new Uint8Array(weiHeader.length + chunk.byteLength);
                        response.set(weiHeader, 0);
                        response.set(chunk, weiHeader.length);
                        webSocket.send(response.buffer);
                        weiHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}


function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, host, portNum) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() { },
        })
    ).catch((err) => {
        closeSocketQuietly(webSocket);
    });
    if (!hasData && retryFunc) {
        console.log(`[connectStreams] ${host}:${portNum} 远程连接无数据返回，执行重试逻辑`);
        await retryFunc();
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}


async function 返袋参数获取(request) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    const pathLower = pathname.toLowerCase();
    // 优先使用参数里面的proxyip
    if (searchParams.has('proxyip')) {
        const 路参IP = searchParams.get('proxyip');
        返袋IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
        return;
    } else {
        // 统一处理返袋IP参数 (优先级最高,使用正则一次匹配)
        const proxyMatch = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)(.+)/);
        if (proxyMatch) {
            const 路参IP = proxyMatch[1] === 'proxyip.' ? `proxyip.${proxyMatch[2]}` : proxyMatch[2];
            返袋IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
            return;
        }
    }
}

function sha224(s) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
    s = unescape(encodeURIComponent(s));
    const l = s.length * 8; s += String.fromCharCode(0x80);
    while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
    const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
    s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
    const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
    for (let i = 0; i < w.length; i += 16) {
        const x = new Array(64).fill(0);
        for (let j = 0; j < 16; j++)x[j] = w[i + j];
        for (let j = 16; j < 64; j++) {
            const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
            const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
            x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h0] = h;
        for (let j = 0; j < 64; j++) {
            const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
            const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
            h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
    }
    let hex = '';
    for (let i = 0; i < 7; i++) {
        for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
    }
    return hex;
}

async function 解析地址端口(pryip, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
    if (!pryip) {
        return null;
    }
    if (!缓存返袋IP || !缓存返袋解析数组 || 缓存返袋IP !== pryip) {
        pryip = pryip.toLowerCase();
        async function DoH查询(域名, 记录类型) {
            try {
                const response = await fetch(`https://1.1.1.1/dns-query?name=${域名}&type=${记录类型}`, {
                    headers: { 'Accept': 'application/dns-json' }
                });
                if (!response.ok) return [];
                const data = await response.json();
                return data.Answer || [];
            } catch (error) {
                console.error(`DoH查询失败 (${记录类型}):`, error);
                return [];
            }
        }

        function 解析地址端口字符串(str) {
            let 地址 = str, 端口 = 443;
            if (str.includes(']:')) {
                const parts = str.split(']:');
                地址 = parts[0] + ']';
                端口 = parseInt(parts[1], 10) || 端口;
            } else if (str.includes(':') && !str.startsWith('[')) {
                const colonIndex = str.lastIndexOf(':');
                地址 = str.slice(0, colonIndex);
                端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
            }
            return [地址, 端口];
        }

        let 所有返袋数组 = [];

        if (pryip.includes('.william')) {
            try {
                const txtRecords = await DoH查询(pryip, 'TXT');
                const txtData = txtRecords.filter(r => r.type === 16).map(r => r.data);
                if (txtData.length > 0) {
                    let data = txtData[0];
                    if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
                    const prefixes = data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
                    所有返袋数组 = prefixes.map(prefix => 解析地址端口字符串(prefix));
                }
            } catch (error) {
                console.error('解析William域名失败:', error);
            }
        } else {
            let [地址, 端口] = 解析地址端口字符串(pryip);

            if (pryip.includes('.tp')) {
                const tpMatch = pryip.match(/\.tp(\d+)/);
                if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
            }

            // 判断是否是域名（非IP地址）
            const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
            const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;

            if (!ipv4Regex.test(地址) && !ipv6Regex.test(地址)) {
                // 并行查询 A 和 AAAA 记录
                const [aRecords, aaaaRecords] = await Promise.all([
                    DoH查询(地址, 'A'),
                    DoH查询(地址, 'AAAA')
                ]);

                const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
                const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
                const ipAddresses = [...ipv4List, ...ipv6List];

                所有返袋数组 = ipAddresses.length > 0
                    ? ipAddresses.map(ip => [ip, 端口])
                    : [[地址, 端口]];
            } else {
                所有返袋数组 = [[地址, 端口]];
            }
        }
        缓存返袋解析数组 = 所有返袋数组;
        // const 排序后数组 = 所有返袋数组.sort((a, b) => a[0].localeCompare(b[0]));
        // const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
        // let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
        // console.log(`[返袋解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`)
        // const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
        // 缓存返袋解析数组 = 洗牌后.slice(0, 100);
        console.log(`[返袋解析] 解析完成 总数: ${缓存返袋解析数组.length}个\n${缓存返袋解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
        缓存返袋IP = pryip;
    } else console.log(`[返袋解析] 读取缓存 总数: ${缓存返袋解析数组.length}个\n${缓存返袋解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
    return 缓存返袋解析数组;
}

async function validPxyIp(pxyip, port) {
    console.log(`[返袋IP验证] ${pxyip}${port ? ":" + port : ""}`);
    const testApi = `${atob("aHR0cHM6Ly9jaGVjay5wcm94eWlwLmNtbGl1c3Nzcy5uZXQvY2hlY2s")}?proxyip=${pxyip}${port ? ":" + port : ""}`
    const response = await fetch(testApi);
    if (response.ok) {
        const result = await response.json();
        console.log(`[返袋IP验证结果] ${result.proxyIP}:${result.portRemote} - 地区：${result.loc}--${result.city}, 可用性: ${result.success}, 响应时间: ${result.responseTime}ms`);
        return result.success;
    } else {
        console.log(`[返袋IP验证结果] 请求失败，状态码: ${response.status}`);
        await response.body.cancel();
    }
    console.log(`[返袋IP验证结果] ${pxyip}${port ? ":" + port : ""} - 不可用！`);
    return false;
}
