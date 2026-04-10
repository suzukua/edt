import {DurableObject} from 'cloudflare:workers';
import {connect} from "cloudflare:sockets";
import { Stream } from 'new-streams';

let 返袋IP = '';
let 缓存返袋IP, 缓存返袋解析数组, 缓存返袋数组索引 = 0;
// 在模块顶部重用 TextDecoder（避免每次 new）
const _TEXT_DECODER = new TextDecoder();
let TOKEN_BYTES, //全局TOKEN
    调试日志打印 = true;

///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
    async fetch(request, env, ctx) {
        const upgradeHeader = request.headers.get('Upgrade');
        let xxooId = '';
        if (env.xxoo && env.xxoo.get) {
            xxooId = await env.xxoo.get()
        }
        const url = new URL(request.url);
        const stub = await getDo(env, url.searchParams.get(`colo`) || request.cf.colo)
        if (stub) {
            return stub.fetch(request, {headers: {...Object.fromEntries(request.headers), "userid": xxooId}});
        } else {
            if (upgradeHeader === 'websocket'){
                返袋参数获取(request);
                return 处理WS请求(request, xxooId);
            } else {
                const referer = request.headers.get('Referer') || '';
                const 命中XHP特征 = referer.includes('x_padding', 14) || referer.includes('x_padding=');
                if (命中XHP特征) {
                    console.log(`[XHTTP] 命中请求: ${url.pathname}${url.search}`);
                    return await 处理XHP请求(request, xxooId);
                }
                return processNoneWebSocket(request);
            }
        }
    }
};

function log(...args) {
    if (调试日志打印) console.log(...args);
}


function getDo(env, cfColo){
    if (!env.WsBigDo) {
        return null;
    }
    const doLocation = env.REGION || "apac";
    const name = `user-${cfColo || doLocation}`;
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
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader === 'websocket') {
            const userId = request.headers.get('userid');
            返袋参数获取(request);
            return 处理WS请求(request, userId);
        } else {
            return processNoneWebSocket(request);
        }
    }
}


///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
function 处理WS请求(request, yourUUID) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    // 增加 writer 缓存，避免重复加锁/解锁带来的性能损耗
    let remoteConnWrapper = { socket: null, writer: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);

    // 采用 for await...of 替代旧的 pipeTo(new WritableStream)，极大降低 GC 压力
    (async () => {
        for await (const chunks of readable) {
            for (const chunk of chunks) {
                if (isDnsQuery) {
                    await forwardataudp(chunk, serverSock, null);
                    continue;
                }
                if (remoteConnWrapper.socket) {
                    if (!remoteConnWrapper.writer) {
                        remoteConnWrapper.writer = remoteConnWrapper.socket.writable.getWriter();
                    }
                    await remoteConnWrapper.writer.write(chunk);
                    continue;
                }
                const {hasError, message, port, hostname, version, isUDP,rawData } = 解析魏烈思请求(chunk, yourUUID);
                if (hasError) {
                    console.log("[请求解析错误] 关闭连接", message);
                    return closeSocketQuietly(serverSock);
                }
                if (isUDP) {
                    if (port === 53){
                        isDnsQuery = true;
                    } else {
                        throw new Error('UDP is not supported');
                    }
                }
                const respHeader = new Uint8Array([version[0], 0]);
                if (isDnsQuery) {
                    await forwardataudp(rawData, serverSock, respHeader);
                    continue;
                }
                await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper);
            }
        }
    })();
    return new Response(null, { status: 101, webSocket: clientSock });
}

async function 处理XHP请求(request, xxooId) {
    if (!request.body) return new Response('Bad Request', { status: 400 });
    const reader = request.body.getReader();
    const 首包 = await 读取XHP首包(reader, xxooId);
    if (!首包) {
        try { reader.releaseLock() } catch (e) { }
        return new Response('Invalid request', { status: 400 });
    }
    if (首包.isUDP && 首包.port !== 53) {
        try { reader.releaseLock() } catch (e) { }
        return new Response('UDP is not supported', { status: 400 });
    }

    const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
    let 当前写入Socket = null;
    let 远端写入器 = null;
    const responseHeaders = new Headers({
        'Content-Type': 'application/octet-stream',
        'X-Accel-Buffering': 'no',
        'Cache-Control': 'no-store'
    });

    const 释放远端写入器 = () => {
        if (远端写入器) {
            try { 远端写入器.releaseLock() } catch (e) { }
            远端写入器 = null;
        }
        当前写入Socket = null;
    };

    const 获取远端写入器 = () => {
        const socket = remoteConnWrapper.socket;
        if (!socket) return null;
        if (socket !== 当前写入Socket) {
            释放远端写入器();
            当前写入Socket = socket;
            远端写入器 = socket.writable.getWriter();
        }
        return 远端写入器;
    };

    return new Response(new ReadableStream({
        async start(controller) {
            let 已关闭 = false;
            let udpRespHeader = 首包.respHeader;
            const XHPBridge = {
                readyState: WebSocket.OPEN,
                send(data) {
                    if (已关闭) return;
                    try {
                        const chunk = data instanceof Uint8Array
                            ? data
                            : data instanceof ArrayBuffer
                                ? new Uint8Array(data)
                                : ArrayBuffer.isView(data)
                                    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
                                    : new Uint8Array(data);
                        controller.enqueue(chunk);
                    } catch (e) {
                        已关闭 = true;
                        this.readyState = WebSocket.CLOSED;
                    }
                },
                close() {
                    if (已关闭) return;
                    已关闭 = true;
                    this.readyState = WebSocket.CLOSED;
                    try { controller.close() } catch (e) { }
                }
            };

            const 写入远端 = async (payload, allowRetry = true) => {
                const writer = 获取远端写入器();
                if (!writer) return false;
                try {
                    await writer.write(payload);
                    return true;
                } catch (err) {
                    释放远端写入器();
                    if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
                        await remoteConnWrapper.retryConnect();
                        return await 写入远端(payload, false);
                    }
                    throw err;
                }
            };

            try {
                if (首包.isUDP) {
                    if (首包.rawData?.byteLength) {
                        await forwardataudp(首包.rawData, XHPBridge, udpRespHeader);
                        udpRespHeader = null;
                    }
                } else {
                    await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, XHPBridge, 首包.respHeader, remoteConnWrapper, xxooId);
                }

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (!value || value.byteLength === 0) continue;
                    if (首包.isUDP) {
                        await forwardataudp(value, XHPBridge, udpRespHeader);
                        udpRespHeader = null;
                    } else {
                        if (!(await 写入远端(value))) throw new Error('Remote socket is not ready');
                    }
                }

                if (!首包.isUDP) {
                    const writer = 获取远端写入器();
                    if (writer) {
                        try { await writer.close() } catch (e) { }
                    }
                }
            } catch (err) {
                log(`[XHP转发] 处理失败: ${err?.message || err}`);
                closeSocketQuietly(XHPBridge);
            } finally {
                释放远端写入器();
                try { reader.releaseLock() } catch (e) { }
            }
        },
        cancel() {
            释放远端写入器();
            try { remoteConnWrapper.socket?.close() } catch (e) { }
            try { reader.releaseLock() } catch (e) { }
        }
    }), { status: 200, headers: responseHeaders });
}

async function 读取XHP首包(reader, token) {
    const decoder = new TextDecoder();
    const 密码哈希 = sha224(token);
    const 密码哈希字节 = new TextEncoder().encode(密码哈希);

    const 尝试解析VLESS首包 = (data) => {
        const length = data.byteLength;
        if (length < 18) return { 状态: 'need_more' };
        const view = data instanceof Uint8Array ? data : new Uint8Array(data);
        if (!TOKEN_BYTES) {
            TOKEN_BYTES = uuidToBytes(token)
        }
        if (!equal16(view, 1, TOKEN_BYTES)) {
            return { hasError: true, message: 'Invalid uuid' };
        }

        const optLen = data[17];
        const cmdIndex = 18 + optLen;
        if (length < cmdIndex + 1) return { 状态: 'need_more' };

        const cmd = data[cmdIndex];
        if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };

        const portIndex = cmdIndex + 1;
        if (length < portIndex + 3) return { 状态: 'need_more' };

        const port = (data[portIndex] << 8) | data[portIndex + 1];
        const addressType = data[portIndex + 2];
        const addressIndex = portIndex + 3;
        let headerLen = -1;
        let hostname = '';

        if (addressType === 1) {
            if (length < addressIndex + 4) return { 状态: 'need_more' };
            hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
            headerLen = addressIndex + 4;
        } else if (addressType === 2) {
            if (length < addressIndex + 1) return { 状态: 'need_more' };
            const domainLen = data[addressIndex];
            if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' };
            hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
            headerLen = addressIndex + 1 + domainLen;
        } else if (addressType === 3) {
            if (length < addressIndex + 16) return { 状态: 'need_more' };
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                const base = addressIndex + i * 2;
                ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
            }
            hostname = ipv6.join(':');
            headerLen = addressIndex + 16;
        } else return { 状态: 'invalid' };

        if (!hostname) return { 状态: 'invalid' };

        return {
            状态: 'ok',
            结果: {
                协议: 'vl' + 'ess',
                hostname,
                port,
                isUDP: cmd === 2,
                rawData: data.subarray(headerLen),
                respHeader: new Uint8Array([data[0], 0]),
            }
        };
    };

    const 尝试解析木马首包 = (data) => {
        const length = data.byteLength;
        if (length < 58) return { 状态: 'need_more' };
        if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
        for (let i = 0; i < 56; i++) {
            if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' };
        }

        const socksStart = 58;
        if (length < socksStart + 2) return { 状态: 'need_more' };
        const cmd = data[socksStart];
        if (cmd !== 1) return { 状态: 'invalid' };

        const atype = data[socksStart + 1];
        let cursor = socksStart + 2;
        let hostname = '';

        if (atype === 1) {
            if (length < cursor + 4) return { 状态: 'need_more' };
            hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
            cursor += 4;
        } else if (atype === 3) {
            if (length < cursor + 1) return { 状态: 'need_more' };
            const domainLen = data[cursor];
            if (length < cursor + 1 + domainLen) return { 状态: 'need_more' };
            hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
            cursor += 1 + domainLen;
        } else if (atype === 4) {
            if (length < cursor + 16) return { 状态: 'need_more' };
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                const base = cursor + i * 2;
                ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
            }
            hostname = ipv6.join(':');
            cursor += 16;
        } else return { 状态: 'invalid' };

        if (!hostname) return { 状态: 'invalid' };
        if (length < cursor + 4) return { 状态: 'need_more' };

        const port = (data[cursor] << 8) | data[cursor + 1];
        if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 状态: 'invalid' };
        const dataOffset = cursor + 4;

        return {
            状态: 'ok',
            结果: {
                协议: 'trojan',
                hostname,
                port,
                isUDP: false,
                rawData: data.subarray(dataOffset),
                respHeader: null,
            }
        };
    };

    let buffer = new Uint8Array(1024);
    let offset = 0;

    while (true) {
        const { value, done } = await reader.read();
        if (done) {
            if (offset === 0) return null;
            break;
        }

        const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
        if (offset + chunk.byteLength > buffer.byteLength) {
            const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
            newBuffer.set(buffer.subarray(0, offset));
            buffer = newBuffer;
        }

        buffer.set(chunk, offset);
        offset += chunk.byteLength;

        const 当前数据 = buffer.subarray(0, offset);
        const 木马结果 = 尝试解析木马首包(当前数据);
        if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };

        const vless结果 = 尝试解析VLESS首包(当前数据);
        if (vless结果.状态 === 'ok') return { ...vless结果.结果, reader };

        if (木马结果.状态 === 'invalid' && vless结果.状态 === 'invalid') return null;
    }

    const 最终数据 = buffer.subarray(0, offset);
    const 最终木马结果 = 尝试解析木马首包(最终数据);
    if (最终木马结果.状态 === 'ok') return { ...最终木马结果.结果, reader };
    const 最终VLESS结果 = 尝试解析VLESS首包(最终数据);
    if (最终VLESS结果.状态 === 'ok') return { ...最终VLESS结果.结果, reader };
    return null;
}

function uuidToBytes(uuid) {
    const clean = uuid.replace(/-/g, '');
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
}


function equal16(a, offset, b) {
    for (let i = 0; i < 16; i++) {
        if (a[offset + i] !== b[i]) return false;
    }
    return true;
}

function 解析魏烈思请求(chunk, token) {
    // 确保是 Uint8Array view（不复制内存）
    const view = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
    const len = view.length;

    // 最小长度校验（早返回，减少后续工作）
    if (len < 24) return { hasError: true, message: `Invalid data, chunk size:${chunk.length}` };

    // 版本：直接用数字（不用 new Uint8Array）
    const version = view[0];

    if (!TOKEN_BYTES) {
        TOKEN_BYTES = uuidToBytes(token)
    }
    if (!equal16(view, 1, TOKEN_BYTES)) {
        return { hasError: true, message: 'Invalid uuid' };
    }

    // 可选字段长度
    const optLen = view[17];

    // cmd 在 18 + optLen 位置，先做边界检查
    const cmdIdx = 18 + optLen;
    if (cmdIdx >= len) return { hasError: true, message: 'Truncated data (cmd)' };
    const cmd = view[cmdIdx];
    let isUDP = false;
    if (cmd === 1) {
        // tcp
    } else if (cmd === 2) {
        isUDP = true;
    } else {
        return { hasError: true, message: `command ${cmd} is not supported, command 01-tcp,02-udp,03-mux` };
    }

    // port 在 19 + optLen，使用单一 DataView（不创建多个）
    const portIdx = 19 + optLen;
    if (portIdx + 2 > len) return { hasError: true, message: 'Truncated data (port)' };
    const dv = new DataView(view.buffer, view.byteOffset, view.byteLength);
    const port = dv.getUint16(portIdx); // 与原实现保持大端（DataView 默认 big-endian）

    // address parsing
    let addrIdx = portIdx + 2;
    if (addrIdx >= len) return { hasError: true, message: 'Truncated data (addr type)' };
    const addressType = view[addrIdx];
    let addrValIdx = addrIdx + 1;
    let hostname = '';
    let addrLen = 0;

    switch (addressType) {
        case 1: // IPv4
            addrLen = 4;
            if (addrValIdx + addrLen > len) return { hasError: true, message: 'Truncated data (ipv4)' };
            // 直接拼字符串，避免在中间创建数组
            hostname = `${view[addrValIdx]}.${view[addrValIdx + 1]}.${view[addrValIdx + 2]}.${view[addrValIdx + 3]}`;
            break;

        case 2: // domain name (length-prefixed)
            if (addrValIdx >= len) return { hasError: true, message: 'Truncated data (domain len)' };
            addrLen = view[addrValIdx];
            addrValIdx += 1;
            if (addrValIdx + addrLen > len) return { hasError: true, message: 'Truncated data (domain)' };
            // 使用重用的 TextDecoder（高效）
            hostname = _TEXT_DECODER.decode(view.subarray(addrValIdx, addrValIdx + addrLen));
            break;

        case 3: // IPv6 (16 bytes)
            addrLen = 16;
            if (addrValIdx + addrLen > len) return { hasError: true, message: 'Truncated data (ipv6)' };
            // 逐段读取 uint16 并转 16 进制，避免创建多余的中间 TypedArray
            const parts = [];
            for (let i = 0; i < 8; i++) {
                // DataView 偏移为 addrValIdx + i*2（单位字节）
                parts.push(dv.getUint16(addrValIdx + i * 2).toString(16));
            }
            hostname = parts.join(':');
            break;

        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }

    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };

    return { hasError: false, port, hostname, isUDP, version, rawData: view.subarray(addrValIdx + addrLen) };
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper) {
    console.log(`[TCP转发] 目标: ${host}:${portNum} | 返袋IP: ${返袋IP} | 返袋类型: pryip}`);

    async function connectPxy(address, port, data, 所有返袋数组 = null, 返袋兜底 = true) {
        let remoteSock;
        if (所有返袋数组 && 所有返袋数组.length > 0) {
            for (let i = 缓存返袋数组索引; i < 所有返袋数组.length; i++) {
                const [返袋地址, 返袋端口] = 所有返袋数组[i];
                try {
                    console.log(`[返袋连接] 尝试连接到: ${返袋地址}:${返袋端口} (索引: ${i})`);
                    await validPxyIp(返袋地址, 返袋端口);
                    remoteSock = connect({ hostname: 返袋地址, port: 返袋端口 });
                    await Promise.race([
                        remoteSock.opened,
                        new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), 1000))
                    ]);
                    if (getLength(data)) {
                        const testWriter = remoteSock.writable.getWriter();
                        try {
                            await testWriter.write(data);
                        } finally {
                            testWriter.releaseLock(); // 无论成功失败，必须释放锁
                        }
                    }
                    console.log(`[返袋连接] 成功连接到: ${返袋地址}:${返袋端口}`);
                    缓存返袋数组索引 = i;
                    return remoteSock;
                } catch (err) {
                    console.log(`[返袋连接] 连接失败: ${返袋地址}:${返袋端口}, 错误: ${err.message}`);
                    try { remoteSock?.close?.(); } catch (e) { }
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
            if (getLength(data)) {
                const writer = remoteSock.writable.getWriter();
                try {
                    await writer.write(data);
                } finally {
                    writer.releaseLock(); // 无论成功失败，必须释放锁
                }
            }
            return remoteSock;
        } else {
            closeSocketQuietly(ws);
            throw new Error('[返袋连接] 所有返袋连接失败，且未启用返袋兜底，连接终止。');
        }
    }

    async function connectDirect(address, port, data) {
        let remoteSock = connect({ hostname: address, port: port });
        if (getLength(data)) {
            const writer = remoteSock.writable.getWriter();
            try {
                await writer.write(data);
            } finally {
                writer.releaseLock(); // 无论成功失败，必须释放锁
            }
        }
        return remoteSock;
    }

    async function connecttoPry() {
        console.log(`[返袋连接] 代理到: ${host}:${portNum}, 反代IP：${返袋IP}`);
        const 所有返袋数组 = await 解析地址端口(返袋IP);
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
        console.log(`[TCP转发] 直连失败: ${err.message}。${host}:${portNum}， 通过返袋重试`);
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

        // 采用 for await 替代 pipeTo，优化资源占用
        await (async () => {
            try {
                for await (const chunk of tcpSocket.readable) {
                    if (webSocket.readyState !== WebSocket.OPEN) break;
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
            } catch (error) {
                // Ignore disconnect errors
            }
        })();
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

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, host, portNum) {
    let header = headerData, hasData = false;
    try {
        // 使用现代的迭代流语法，避开原有的 WritableStream 初始化样板
        for await (const chunk of remoteSocket.readable) {
            hasData = true;
            console.log(`[数据转发] ${host}:${portNum} - 转发数据块，大小: ${chunk.byteLength} bytes, ${webSocket.readyState !== WebSocket.OPEN}`);
            if (webSocket.readyState !== WebSocket.OPEN) break;
            if (header) {
                const response = new Uint8Array(header.length + chunk.byteLength);
                response.set(header, 0);
                response.set(chunk, header.length);
                webSocket.send(response.buffer);
                header = null;
            } else {
                webSocket.send(chunk);
            }
        }
    } catch (err) {
        console.log(`[数据转发] ${host}:${portNum} - 转发过程中发生错误: ${err.message} `);
    } finally {
        if (!hasData && retryFunc) {
            console.log(`[connectStreams] ${host}:${portNum} 远程连接无数据返回，执行重试逻辑`);
            await retryFunc();
        } else {
            //没有重试函数且已经有数据传输，说明是连接中途发生错误，记录日志但不执行重试逻辑
            console.log(`[connectStreams] ${host}:${portNum} 连接结束，已传输数据: ${hasData}, 不执行重试逻辑`);
            closeSocketQuietly(webSocket);
        }
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    const { writer, readable } = Stream.push({
        highWaterMark: 16,          // 控制缓冲大小
        backpressure: 'block'       // 满时阻塞，防止内存膨胀
    });
    socket.addEventListener('message', (event) => {
        if (cancelled) return;
        try {
            const data = event.data;
            // 确保是 Uint8Array
            const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
            // 单块写入（如果你有分包，可改成 writev）
            writer.write(chunk);
        } catch (err) {
            writer.fail(err);
        }
    });
    socket.addEventListener('close', () => {
        if (!cancelled) {
            cancelled = true;
            closeSocketQuietly(socket);
            writer.end();
        }
    });
    socket.addEventListener('error', (err) => {
        writer.fail(err);
    });

    // 处理 early data
    const { earlyData, error } = base64ToArray(earlyDataHeader);
    if (error) {
        writer.fail(error);
    } else if (earlyData) {
        writer.write(earlyData);
    }
    // 返回的是 AsyncIterable<Uint8Array[]>
    return readable;
    // return new ReadableStream({
    //     start(controller) {
    //         socket.addEventListener('message', (event) => {
    //             if (!cancelled) controller.enqueue(event.data);
    //         });
    //         socket.addEventListener('close', () => {
    //             if (!cancelled) {
    //                 closeSocketQuietly(socket);
    //                 controller.close();
    //             }
    //         });
    //         socket.addEventListener('error', (err) => controller.error(err));
    //         const { earlyData, error } = base64ToArray(earlyDataHeader);
    //         if (error) controller.error(error);
    //         else if (earlyData) controller.enqueue(earlyData);
    //     },
    //     cancel() {
    //         cancelled = true;
    //         closeSocketQuietly(socket);
    //     }
    // });
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

function processNoneWebSocket(request) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase();
    if (path == '/reset/pxy') {
        缓存返袋解析数组 = null;
        缓存返袋数组索引 = 0;
        return new Response(getViewJSON(), {headers: {"Content-Type": "application/json; charset=utf-8"}});
    } else {
        return new Response(viewHtml(), {headers: {"Content-Type": "text/html; charset=utf-8"}});
    }
}

function 返袋参数获取(request) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    // 优先使用参数里面的proxyip
    if (searchParams.has('proxyip')) {
        const 路参IP = searchParams.get('proxyip');
        返袋IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
        return;
    } else {
        const pathLower = pathname.toLowerCase();
        // 统一处理返袋IP参数 (优先级最高,使用正则一次匹配)
        const proxyMatch = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)(.+)/);
        if (proxyMatch) {
            const 路参IP = proxyMatch[1] === 'proxyip.' ? `proxyip.${proxyMatch[2]}` : proxyMatch[2];
            返袋IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
            return;
        }
    }
}

function getLength(data) {
    if (!data) return 0;
    if (typeof data.byteLength === 'number') return data.byteLength;
    if (typeof data.length === 'number') return data.length;
    return 0;
}

async function 解析地址端口(pryip) {
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
        console.log(`[返袋解析] 解析完成 总数: ${缓存返袋解析数组.length}个\n${缓存返袋解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
        缓存返袋IP = pryip;
    } else {
        console.log(`[返袋解析] 读取缓存 总数: ${缓存返袋解析数组.length}个\n${缓存返袋解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
    }
    return 缓存返袋解析数组;
}

async function validPxyIp(pxyip, port) {
    console.log(`[返袋IP验证] ${pxyip}${port ? ":" + port : ""}`);
    const testApi = `${atob("aHR0cHM6Ly9jaGVjay5wcm94eWlwLmNtbGl1c3Nzcy5uZXQvY2hlY2s")}?proxyip=${pxyip}${port ? ":" + port : ""}`
    const controller = new AbortController()
    setTimeout(() => controller.abort(), 800)
    try {
        const response = await fetch(testApi, {
            signal: controller.signal,
            cf: {
                cacheEverything: true,
                cacheKey: pxyip,
                cacheTtlByStatus: { "200-299": 60, "400-599": -1 }
            }
        })
        const result = await response.json();
        if (result.success) {
            console.log(`[返袋IP验证结果] ${result.proxyIP}:${result.portRemote} - 地区：${result.loc}--${result.city}, 可用性: ${result.success}, 响应时间: ${result.responseTime}ms`);
            return;
        } else {
            console.log(`[返袋IP验证结果] ${pxyip}${port ? ":" + port : ""} - 不可用！`);
            throw new Error('validPxyIp检查到返袋IP不可用');
        }
    } catch (e) {
        console.log(`[返袋IP验证服务发生异常] ${e.message}`);
        throw e
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

function viewHtml(){
    return `
    <!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>Reset Pxy</title>
  <style>
    body {
      font-family: Consolas, Monaco, monospace;
      background: #f6f8fa;
      padding: 20px;
    }
    button {
      padding: 8px 16px;
      font-size: 14px;
      cursor: pointer;
    }
    button,
    .btn-link {
      display: inline-block;
      padding: 8px 16px;
      font-size: 14px;
      cursor: pointer;
      background: #fff;
      border: 1px solid #d0d7de;
      border-radius: 6px;
      text-decoration: none;   /* 去掉a标签下划线 */
      color: #000;
    }
    
    button:hover,
    .btn-link:hover {
      background: #f3f4f6;
    }
    pre {
      margin-top: 16px;
      padding: 16px;
      background: #0d1117;
      color: #c9d1d9;
      border-radius: 6px;
      overflow: auto;
      max-height: 500px;
    }
  </style>
</head>
<body>

  <button id="resetBtn">重置prxy</button>
  <a href="/?colo=NRT" class="btn-link">日本成田机房（NRT）</a>
  <a href="/?colo=SIN" class="btn-link">新加坡机房（SIN）</a>
  <pre id="jsonView">
${getViewJSON()}
  </pre>

  <script>
    const btn = document.getElementById("resetBtn");
    const jsonView = document.getElementById("jsonView");

    btn.addEventListener("click", async () => {
      jsonView.textContent = "请求中...";

      try {
        const resp = await fetch("/reset/pxy" + window.location.search, {
          method: "GET"
        });
        if (!resp.ok) {
          throw new Error("HTTP " + resp.status);
        }
        const data = await resp.json();
        jsonView.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        jsonView.textContent = JSON.stringify({
          error: true,
          message: err.message
        }, null, 2);
      }
    });
  </script>
</body>
</html>
`
}

function getViewJSON(){
    return  JSON.stringify({
        "返袋IP": `${返袋IP}`,
        "缓存返袋IP": `${缓存返袋IP ? 缓存返袋IP : ''}`,
        "缓存返袋数组索引": `${缓存返袋数组索引}`,
        "正在使用的返袋": `${缓存返袋解析数组 ? 缓存返袋解析数组[缓存返袋数组索引].join(':'): ''}`,
        "缓存返袋解析数组": `${缓存返袋解析数组 ? 缓存返袋解析数组.map(item => item.join(':')) : ''}`
    }, null, 2);
}