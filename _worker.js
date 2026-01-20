import { connect } from "cloudflare:sockets";

let config_JSON, 反代IP = '', 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {}, ECH_DOH = 'https://doh.cmliussss.net/CMLiussss';
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = request.headers.get('Upgrade');
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
        const hosts = env.HOST ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
        const host = hosts[0];
        if (env.PROXYIP) {
            const proxyIPs = await 整理成数组(env.PROXYIP);
            反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
        } else {
            反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        }
        const 访问IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || '未知IP';
        if (env.GO2SOCKS5) SOCKS5白名单 = await 整理成数组(env.GO2SOCKS5);
        ECH_DOH = env.ECH_DOH || env.DOH || ECH_DOH;
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
            if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            if (env.KV && typeof env.KV.get === 'function') {
                const 访问路径 = url.pathname.slice(1).toLowerCase();
                const 区分大小写访问路径 = url.pathname.slice(1);
                if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
                    const params = new URLSearchParams(url.search);
                    params.set('token', await MD5MD5(host + userID));
                    return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
                } else if (访问路径 === 'login') {//处理登录页面和登录请求
                    const cookies = request.headers.get('Cookie') || '';
                    const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                    if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
                    if (request.method === 'POST') {
                        const formData = await request.text();
                        const params = new URLSearchParams(formData);
                        const 输入密码 = params.get('password');
                        if (输入密码 === 管理员密码) {
                            // 密码正确，设置cookie并返回成功标记
                            const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly`);
                            return 响应;
                        }
                    }
                    return fetch(Pages静态页面 + '/login');
                } else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {//验证cookie后响应管理页面
                    const cookies = request.headers.get('Cookie') || '';
                    const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                    // 没有cookie或cookie错误，跳转到/login页面
                    if (!authCookie || authCookie !== await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                    if (访问路径 === 'admin/log.json') {// 读取日志内容
                        const 读取日志内容 = await env.KV.get('log.json') || '[]';
                        return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {// 查询请求量
                        try {
                            const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
                            return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                        } catch (err) {
                            const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
                            return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (区分大小写访问路径 === 'admin/getADDAPI') {// 验证优选API
                        if (url.searchParams.get('url')) {
                            const 待验证优选URL = url.searchParams.get('url');
                            try {
                                new URL(待验证优选URL);
                                const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
                                const 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
                                return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (err) {
                                const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
                                return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        }
                        return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } else if (访问路径 === 'admin/check') {// SOCKS5代理检查
                        let 检测代理响应;
                        if (url.searchParams.has('socks5')) {
                            检测代理响应 = await SOCKS5可用性验证('socks5', url.searchParams.get('socks5'));
                        } else if (url.searchParams.has('http')) {
                            检测代理响应 = await SOCKS5可用性验证('http', url.searchParams.get('http'));
                        } else {
                            return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                        return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }

                    config_JSON = await 读取config_JSON(env, host, userID, env.PATH);

                    if (访问路径 === 'admin/init') {// 重置配置为默认值
                        try {
                            config_JSON = await 读取config_JSON(env, host, userID, env.PATH, true);
                            ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
                            config_JSON.init = '配置已重置为默认值';
                            return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (err) {
                            const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
                            return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
                        if (访问路径 === 'admin/config.json') { // 保存config.json配置
                            try {
                                const newConfig = await request.json();
                                // 验证配置完整性
                                if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

                                // 保存到 KV
                                await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存配置失败:', error);
                                return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else if (访问路径 === 'admin/cf.json') { // 保存cf.json配置
                            try {
                                const newConfig = await request.json();
                                const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
                                if (!newConfig.init || newConfig.init !== true) {
                                    if (newConfig.Email && newConfig.GlobalAPIKey) {
                                        CF_JSON.Email = newConfig.Email;
                                        CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
                                    } else if (newConfig.AccountID && newConfig.APIToken) {
                                        CF_JSON.AccountID = newConfig.AccountID;
                                        CF_JSON.APIToken = newConfig.APIToken;
                                    } else if (newConfig.UsageAPI) {
                                        CF_JSON.UsageAPI = newConfig.UsageAPI;
                                    } else {
                                        return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                    }
                                }

                                // 保存到 KV
                                await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存配置失败:', error);
                                return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else if (访问路径 === 'admin/tg.json') { // 保存tg.json配置
                            try {
                                const newConfig = await request.json();
                                if (newConfig.init && newConfig.init === true) {
                                    const TG_JSON = { BotToken: null, ChatID: null };
                                    await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
                                } else {
                                    if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                    await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
                                }
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存配置失败:', error);
                                return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else if (区分大小写访问路径 === 'admin/ADD.txt') { // 保存自定义优选IP
                            try {
                                const customIPs = await request.text();
                                await env.KV.put('ADD.txt', customIPs);// 保存到 KV
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存自定义IP失败:', error);
                                return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } else if (访问路径 === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON
                        return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                    } else if (区分大小写访问路径 === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回本地优选IP
                        let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
                        if (本地优选IP == 'null') 本地优选IP = (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[1];
                        return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
                    } else if (访问路径 === 'admin/cf.json') {// CF配置文件
                        return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }

                    ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
                    return fetch(Pages静态页面 + '/admin');
                } else if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {//清除cookie并跳转到登录页面
                    const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                    响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
                    return 响应;
                } else if (访问路径 === 'sub') {//处理订阅请求
                    const 订阅TOKEN = await MD5MD5(host + userID);
                    if (url.searchParams.get('token') === 订阅TOKEN) {
                        config_JSON = await 读取config_JSON(env, host, userID, env.PATH);
                        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
                        const ua = UA.toLowerCase();
                        const expire = 4102329600;//2099-12-31 到期时间
                        const now = Date.now();
                        const today = new Date(now);
                        today.setHours(0, 0, 0, 0);
                        const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                        let pagesSum = UD, workersSum = UD, total = 24 * 1099511627776;
                        // if (config_JSON.CF.Usage.success) {
                        //     pagesSum = config_JSON.CF.Usage.pages;
                        //     workersSum = config_JSON.CF.Usage.workers;
                        //     total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
                        // }
                        if (config_JSON.CF.DoUsage.success) {
                            pagesSum = 0;
                            workersSum = config_JSON.CF.DoUsage.total;
                            total = Number.isFinite(config_JSON.CF.DoUsage.max) ? (config_JSON.CF.DoUsage.max / 1000) * 1024 : 1024 * 100;
                        }
                        const responseHeaders = {
                            "content-type": "text/plain; charset=utf-8",
                            "Profile-Update-Interval": config_JSON.优选订阅生成.SUBUpdateTime,
                            "Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
                            "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            "Cache-Control": "no-store",
                        };
                        const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase());
                        const 订阅类型 = isSubConverterRequest
                            ? 'mixed'
                            : url.searchParams.has('target')
                                ? url.searchParams.get('target')
                                : url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
                                    ? 'clash'
                                    : url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
                                        ? 'singbox'
                                        : url.searchParams.has('surge') || ua.includes('surge')
                                            ? 'surge&ver=4'
                                            : url.searchParams.has('quanx') || ua.includes('quantumult')
                                                ? 'quanx'
                                                : url.searchParams.has('loon') || ua.includes('loon')
                                                    ? 'loon'
                                                    : 'mixed';

                        if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
                        const 协议类型 = (url.searchParams.has('surge') || ua.includes('surge')) ? 'tro' + 'jan' : config_JSON.协议类型;
                        let 订阅内容 = '';
                        if (订阅类型 === 'mixed') {
                            let 节点路径 = config_JSON.PATH.replace(`/proxyip=`,`?proxyip=`);
                            if (config_JSON.启用0RTT) {
                                节点路径 += 节点路径.includes("?proxyip=") ? '&ed=2560' : '?ed=2560';
                            }
                            config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH;
                            const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
                            let 完整优选IP = [], 其他节点LINK = '';

                            if (!url.searchParams.has('sub') && config_JSON.优选订阅生成.local) { // 本地生成订阅
                                const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP ? (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[0] : await env.KV.get('ADD.txt') ? await 整理成数组(await env.KV.get('ADD.txt')) : (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[0];
                                const 优选API = [], 优选IP = [], 其他节点 = [];
                                for (const 元素 of 完整优选列表) {
                                    if (元素.toLowerCase().startsWith('https://')) 优选API.push(元素);
                                    else if (元素.toLowerCase().includes('://')) {
                                        if (元素.includes('#')) {
                                            const 地址备注分离 = 元素.split('#');
                                            其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
                                        } else 其他节点.push(元素);
                                    } else 优选IP.push(元素);
                                }
                                const 请求优选API内容 = await 请求优选API(优选API);
                                const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
                                其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
                                const 优选API的IP = 请求优选API内容[0];
                                完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
                            } else { // 优选订阅生成器
                                let 优选订阅生成器HOST = url.searchParams.get('sub') || config_JSON.优选订阅生成.SUB;
                                优选订阅生成器HOST = 优选订阅生成器HOST && !/^https?:\/\//i.test(优选订阅生成器HOST) ? `https://${优选订阅生成器HOST}` : 优选订阅生成器HOST;
                                const 优选订阅生成器URL = `${优选订阅生成器HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;
                                try {
                                    const response = await fetch(优选订阅生成器URL, { headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' } });
                                    if (!response.ok) return new Response('优选订阅生成器异常：' + response.statusText, { status: response.status });
                                    const 优选订阅生成器返回订阅内容 = atob(await response.text());
                                    const 订阅行列表 = 优选订阅生成器返回订阅内容.includes('\r\n') ? 优选订阅生成器返回订阅内容.split('\r\n') : 优选订阅生成器返回订阅内容.split('\n');
                                    for (const 行内容 of 订阅行列表) {
                                        if (!行内容.trim()) continue; // 跳过空行
                                        if (行内容.includes('00000000-0000-4000-8000-000000000000') && 行内容.includes('example.com')) { // 这是优选IP行，提取 域名:端口#备注
                                            const 地址匹配 = 行内容.match(/:\/\/[^@]+@([^?]+)/);
                                            if (地址匹配) {
                                                let 地址端口 = 地址匹配[1], 备注 = ''; // 域名:端口 或 IP:端口
                                                const 备注匹配 = 行内容.match(/#(.+)$/);
                                                if (备注匹配) 备注 = '#' + decodeURIComponent(备注匹配[1]);
                                                完整优选IP.push(地址端口 + 备注);
                                            }
                                        } else 其他节点LINK += 行内容 + '\n';
                                    }
                                } catch (error) {
                                    return new Response('优选订阅生成器异常：' + error.message, { status: 403 });
                                }
                            }
                            const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent('cloudflare-ech.com+' + ECH_DOH)}` : '';
                            订阅内容 = 其他节点LINK + 完整优选IP.map(原始地址 => {
                                // 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
                                // 示例: 
                                //   - 域名: hj.xmm1993.top:2096#备注 或 example.com
                                //   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
                                //   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
                                const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
                                const match = 原始地址.match(regex);

                                let 节点地址, 节点端口 = "443", 节点备注;

                                if (match) {
                                    节点地址 = match[1];  // IP地址或域名(可能带方括号)
                                    节点端口 = match[2] || "443";  // 端口,默认443
                                    节点备注 = match[3] || 节点地址;  // 备注,默认为地址本身
                                } else {
                                    // 不规范的格式，跳过处理返回null
                                    console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
                                    return null;
                                }

                                return `${协议类型}://00000000-0000-4000-8000-000000000000@${节点地址}:${节点端口}?security=tls&type=${config_JSON.传输协议 + ECHLINK参数}&host=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&path=${encodeURIComponent(config_JSON.随机路径 ? 随机路径() + 节点路径 : 节点路径) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(节点备注)}`;
                            }).filter(item => item !== null).join('\n');
                        } else { // 订阅转换
                            const 订阅转换URL = `${config_JSON.订阅转换配置.SUBAPI}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 订阅TOKEN + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG)}&emoji=${config_JSON.订阅转换配置.SUBEMOJI}&scv=${config_JSON.跳过证书验证}`;
                            try {
                                const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter for ' + 订阅类型 + ' edge' + 'tunnel(https://github.com/cmliu/edge' + 'tunnel)' } });
                                if (response.ok) {
                                    订阅内容 = await response.text();
                                    if (url.searchParams.has('surge') || ua.includes('surge')) 订阅内容 = Surge订阅配置文件热补丁(订阅内容, url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge', config_JSON);
                                } else return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
                            } catch (error) {
                                return new Response('订阅转换后端异常：' + error.message, { status: 403 });
                            }
                        }

                        if (!ua.includes('subconverter')) 订阅内容 = await 批量替换域名(订阅内容.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID), config_JSON.HOSTS)

                        if (订阅类型 === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) 订阅内容 = btoa(订阅内容);

                        if (订阅类型 === 'singbox') {
                            订阅内容 = Singbox订阅配置文件热补丁(订阅内容, config_JSON.UUID, config_JSON.Fingerprint, config_JSON.ECH ? await getECH(host) : null);
                            responseHeaders["content-type"] = 'application/json; charset=utf-8';
                        } else if (订阅类型 === 'clash') {
                            订阅内容 = Clash订阅配置文件热补丁(订阅内容, config_JSON.UUID, config_JSON.ECH);
                            responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
                        }
                        return new Response(订阅内容, { status: 200, headers: responseHeaders });
                    }
                } else if (访问路径 === 'locations') {//反代locations列表
                    const cookies = request.headers.get('Cookie') || '';
                    const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                    if (authCookie && authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
                } else if (访问路径 === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
            } else if (!envUUID) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
        }

        let 伪装页URL = env.URL || 'nginx';
        if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
            伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
            if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
            if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
            try { const u = new URL(伪装页URL); 伪装页URL = u.protocol + '//' + u.host; } catch (e) { 伪装页URL = 'nginx'; }
        }
        if (伪装页URL === '1101') return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
        try {
            const 反代URL = new URL(伪装页URL), 新请求头 = new Headers(request.headers);
            新请求头.set('Host', 反代URL.host);
            新请求头.set('Referer', 反代URL.origin);
            新请求头.set('Origin', 反代URL.origin);
            if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);
            const 反代响应 = await fetch(反代URL.origin + url.pathname + url.search, { method: request.method, headers: 新请求头, body: request.body, cf: request.cf });
            const 内容类型 = 反代响应.headers.get('content-type') || '';
            // 只处理文本类型的响应
            if (/text|javascript|json|xml/.test(内容类型)) {
                const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
                return new Response(响应内容, { status: 反代响应.status, headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' } });
            }
            return 反代响应;
        } catch (error) { }
        return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }
};

////////////////////////////////SOCKS5/HTTP函数///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    try {
        const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        let response = await reader.read();
        if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

        const selectedMethod = new Uint8Array(response.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) throw new Error('S5 requires authentication');
            const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
            await writer.write(authPacket);
            response = await reader.read();
            if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
        } else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
        await writer.write(connectPacket);
        response = await reader.read();
        if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}

async function httpConnect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    try {
        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
        const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await writer.write(new TextEncoder().encode(request));

        let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
        while (headerEndIndex === -1 && bytesRead < 8192) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Connection closed before receiving HTTP response');
            responseBuffer = new Uint8Array([...responseBuffer, ...value]);
            bytesRead = responseBuffer.length;
            const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
            if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
        }

        if (headerEndIndex === -1) throw new Error('Invalid HTTP response');
        const statusCode = parseInt(new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/)[1]);
        if (statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}
//////////////////////////////////////////////////功能性函数///////////////////////////////////////////////
function Clash订阅配置文件热补丁(Clash_原始订阅内容, uuid = null, ECH启用 = false) {
    if (!ECH启用) return Clash_原始订阅内容;

    const clash_yaml = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 101.101.101.101
    - 208.67.220.220
  fallback-filter:
    geoip: true
    domain: [+.google.com, +.facebook.com, +.youtube.com]
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
    geoip-code: CN
  proxy-server-nameserver:
    - https://doh.cmliussss.com/CMLiussss
    - ${ECH_DOH}
` + Clash_原始订阅内容;

    if (!uuid) return clash_yaml;
    const lines = clash_yaml.split('\n');
    const processedLines = [];
    let i = 0;

    while (i < lines.length) {
        const line = lines[i];
        const trimmedLine = line.trim();

        // 处理行格式（Flow）：- {name: ..., uuid: ..., ...}
        if (trimmedLine.startsWith('- {') && (trimmedLine.includes('uuid:') || trimmedLine.includes('password:'))) {
            let fullNode = line;
            let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;

            // 如果括号不匹配，继续读取下一行
            while (braceCount > 0 && i + 1 < lines.length) {
                i++;
                fullNode += '\n' + lines[i];
                braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
            }

            // 获取代理类型
            const typeMatch = fullNode.match(/type:\s*(\w+)/);
            const proxyType = typeMatch ? typeMatch[1] : 'vless';

            // 根据代理类型确定要查找的字段
            let credentialField = 'uuid';
            if (proxyType === 'trojan') {
                credentialField = 'password';
            }

            // 检查对应字段的值是否匹配
            const credentialPattern = new RegExp(`${credentialField}:\\s*([^,}\\n]+)`);
            const credentialMatch = fullNode.match(credentialPattern);

            if (credentialMatch && credentialMatch[1].trim() === uuid.trim()) {
                // 在最后一个}前添加ech-opts
                fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true}}$1`);
            }

            processedLines.push(fullNode);
            i++;
        }
        // 处理块格式（Block）：- name: ..., 后续行为属性
        else if (trimmedLine.startsWith('- name:')) {
            // 收集完整的代理节点定义
            let nodeLines = [line];
            let baseIndent = line.search(/\S/);
            let topLevelIndent = baseIndent + 2; // 顶级属性的缩进
            i++;

            // 继续读取这个节点的所有属性
            while (i < lines.length) {
                const nextLine = lines[i];
                const nextTrimmed = nextLine.trim();

                // 如果是空行，包含它但不继续
                if (!nextTrimmed) {
                    nodeLines.push(nextLine);
                    i++;
                    break;
                }

                const nextIndent = nextLine.search(/\S/);

                // 如果缩进小于等于基础缩进且不是空行，说明节点结束了
                if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
                    break;
                }

                // 如果缩进更小，节点也结束了
                if (nextIndent < baseIndent && nextTrimmed) {
                    break;
                }

                nodeLines.push(nextLine);
                i++;
            }

            // 获取代理类型
            const nodeText = nodeLines.join('\n');
            const typeMatch = nodeText.match(/type:\s*(\w+)/);
            const proxyType = typeMatch ? typeMatch[1] : 'vless';

            // 根据代理类型确定要查找的字段
            let credentialField = 'uuid';
            if (proxyType === 'trojan') {
                credentialField = 'password';
            }

            // 检查这个节点的对应字段是否匹配
            const credentialPattern = new RegExp(`${credentialField}:\\s*([^\\n]+)`);
            const credentialMatch = nodeText.match(credentialPattern);

            if (credentialMatch && credentialMatch[1].trim() === uuid.trim()) {
                // 找到在哪里插入ech-opts
                // 策略：在最后一个顶级属性后面插入，或在ws-opts之前插入
                let insertIndex = -1;

                for (let j = nodeLines.length - 1; j >= 0; j--) {
                    // 跳过空行，找到节点中最后一个非空行（可能是顶级属性或其子项）
                    if (nodeLines[j].trim()) {
                        insertIndex = j;
                        break;
                    }
                }

                if (insertIndex >= 0) {
                    const indent = ' '.repeat(topLevelIndent);
                    // 在节点末尾（最后一个属性块之后）插入 ech-opts 属性
                    nodeLines.splice(insertIndex + 1, 0,
                        `${indent}ech-opts:`,
                        `${indent}  enable: true`
                    );
                }
            }

            processedLines.push(...nodeLines);
        } else {
            processedLines.push(line);
            i++;
        }
    }

    return processedLines.join('\n');
}

function Singbox订阅配置文件热补丁(sb_json_text, uuid = null, fingerprint = "chrome", ech_config = null) {
    try {
        let config = JSON.parse(sb_json_text);

        // --- 1. TUN 入站迁移 (1.10.0+) ---
        if (Array.isArray(config.inbounds)) {
            config.inbounds.forEach(inbound => {
                if (inbound.type === 'tun') {
                    const addresses = [];
                    if (inbound.inet4_address) addresses.push(inbound.inet4_address);
                    if (inbound.inet6_address) addresses.push(inbound.inet6_address);
                    if (addresses.length > 0) {
                        inbound.address = addresses;
                        delete inbound.inet4_address;
                        delete inbound.inet6_address;
                    }

                    const route_addresses = [];
                    if (Array.isArray(inbound.inet4_route_address)) route_addresses.push(...inbound.inet4_route_address);
                    if (Array.isArray(inbound.inet6_route_address)) route_addresses.push(...inbound.inet6_route_address);
                    if (route_addresses.length > 0) {
                        inbound.route_address = route_addresses;
                        delete inbound.inet4_route_address;
                        delete inbound.inet6_route_address;
                    }

                    const route_exclude_addresses = [];
                    if (Array.isArray(inbound.inet4_route_exclude_address)) route_exclude_addresses.push(...inbound.inet4_route_exclude_address);
                    if (Array.isArray(inbound.inet6_route_exclude_address)) route_exclude_addresses.push(...inbound.inet6_route_exclude_address);
                    if (route_exclude_addresses.length > 0) {
                        inbound.route_exclude_address = route_exclude_addresses;
                        delete inbound.inet4_route_exclude_address;
                        delete inbound.inet6_route_exclude_address;
                    }
                }
            });
        }

        // --- 2. 迁移 Geosite/GeoIP 到 rule_set (1.8.0+) 及 Actions (1.11.0+) ---
        const ruleSetsDefinitions = new Map();
        const processRules = (rules, isDns = false) => {
            if (!Array.isArray(rules)) return;
            rules.forEach(rule => {
                if (rule.geosite) {
                    const geositeList = Array.isArray(rule.geosite) ? rule.geosite : [rule.geosite];
                    rule.rule_set = geositeList.map(name => {
                        const tag = `geosite-${name}`;
                        if (!ruleSetsDefinitions.has(tag)) {
                            ruleSetsDefinitions.set(tag, {
                                tag: tag,
                                type: "remote",
                                format: "binary",
                                url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-${name}.srs`,
                                download_detour: "DIRECT"
                            });
                        }
                        return tag;
                    });
                    delete rule.geosite;
                }
                if (rule.geoip) {
                    const geoipList = Array.isArray(rule.geoip) ? rule.geoip : [rule.geoip];
                    rule.rule_set = rule.rule_set || [];
                    geoipList.forEach(name => {
                        const tag = `geoip-${name}`;
                        if (!ruleSetsDefinitions.has(tag)) {
                            ruleSetsDefinitions.set(tag, {
                                tag: tag,
                                type: "remote",
                                format: "binary",
                                url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-${name}.srs`,
                                download_detour: "DIRECT"
                            });
                        }
                        rule.rule_set.push(tag);
                    });
                    delete rule.geoip;
                }
                const targetField = isDns ? 'server' : 'outbound';
                const actionValue = String(rule[targetField]).toUpperCase();
                if (actionValue === 'REJECT' || actionValue === 'BLOCK') {
                    rule.action = 'reject';
                    rule.method = 'drop'; // 强制使用现代方式
                    delete rule[targetField];
                }
            });
        };

        if (config.dns && config.dns.rules) processRules(config.dns.rules, true);
        if (config.route && config.route.rules) processRules(config.route.rules, false);

        if (ruleSetsDefinitions.size > 0) {
            if (!config.route) config.route = {};
            config.route.rule_set = Array.from(ruleSetsDefinitions.values());
        }

        // --- 3. 兼容性与纠错 ---
        if (!config.outbounds) config.outbounds = [];

        // 移除 outbounds 中冗余的 block 类型节点 (如果它们已经被 action 替代)
        // 但保留 DIRECT 这种必需的特殊出站
        config.outbounds = config.outbounds.filter(o => {
            if (o.tag === 'REJECT' || o.tag === 'block') {
                return false; // 移除，因为已经改用 action: reject 了
            }
            return true;
        });

        const existingOutboundTags = new Set(config.outbounds.map(o => o.tag));

        if (!existingOutboundTags.has('DIRECT')) {
            config.outbounds.push({ "type": "direct", "tag": "DIRECT" });
            existingOutboundTags.add('DIRECT');
        }

        if (config.dns && config.dns.servers) {
            const dnsServerTags = new Set(config.dns.servers.map(s => s.tag));
            if (config.dns.rules) {
                config.dns.rules.forEach(rule => {
                    if (rule.server && !dnsServerTags.has(rule.server)) {
                        if (rule.server === 'dns_block' && dnsServerTags.has('block')) {
                            rule.server = 'block';
                        } else if (rule.server.toLowerCase().includes('block') && !dnsServerTags.has(rule.server)) {
                            config.dns.servers.push({ "tag": rule.server, "address": "rcode://success" });
                            dnsServerTags.add(rule.server);
                        }
                    }
                });
            }
        }

        config.outbounds.forEach(outbound => {
            if (outbound.type === 'selector' || outbound.type === 'urltest') {
                if (Array.isArray(outbound.outbounds)) {
                    // 修正：如果选择器引用了被移除的 REJECT/block，直接将其过滤掉
                    // 因为路由规则已经通过 action 拦截了，不需要走选择器
                    outbound.outbounds = outbound.outbounds.filter(tag => {
                        const upperTag = tag.toUpperCase();
                        return existingOutboundTags.has(tag) && upperTag !== 'REJECT' && upperTag !== 'BLOCK';
                    });
                    if (outbound.outbounds.length === 0) outbound.outbounds.push("DIRECT");
                }
            }
        });

        // --- 4. UUID 匹配节点的 TLS 热补丁 (utls & ech) ---
        if (uuid) {
            config.outbounds.forEach(outbound => {
                // 仅处理包含 uuid 或 password 且匹配的节点
                if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
                    // 确保 tls 对象存在
                    if (!outbound.tls) {
                        outbound.tls = { enabled: true };
                    }

                    // 添加/更新 utls 配置
                    if (fingerprint) {
                        outbound.tls.utls = {
                            enabled: true,
                            fingerprint: fingerprint
                        };
                    }

                    // 如果提供了 ech_config，添加/更新 ech 配置
                    if (ech_config) {
                        outbound.tls.ech = {
                            enabled: true,
                            config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
                        };
                    }
                }
            });
        }

        return JSON.stringify(config, null, 2);
    } catch (e) {
        console.error("Singbox热补丁执行失败:", e);
        return JSON.stringify(JSON.parse(sb_json_text), null, 2);
    }
}

function Surge订阅配置文件热补丁(content, url, config_JSON) {
    const 每行内容 = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');

    let 输出内容 = "";
    const realSurgePath = config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH;
    for (let x of 每行内容) {
        if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
            const host = x.split("sni=")[1].split(",")[0];
            const 备改内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}`;
            const 正确内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}, ws=true, ws-path=${realSurgePath}, ws-headers=Host:"${host}"`;
            输出内容 += x.replace(new RegExp(备改内容, 'g'), 正确内容).replace("[", "").replace("]", "") + '\n';
        } else {
            输出内容 += x + '\n';
        }
    }

    输出内容 = `#!MANAGED-CONFIG ${url} interval=${config_JSON.优选订阅生成.SUBUpdateTime * 60 * 60} strict=false` + 输出内容.substring(输出内容.indexOf('\n'));
    return 输出内容;
}

async function 请求日志记录(env, request, 访问IP, 请求类型 = "Get_SUB", config_JSON) {
    const KV容量限制 = 4;//MB
    try {
        const 当前时间 = new Date();
        const 日志内容 = { TYPE: 请求类型, IP: 访问IP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: 当前时间.getTime() };
        let 日志数组 = [];
        const 现有日志 = await env.KV.get('log.json');
        if (现有日志) {
            try {
                日志数组 = JSON.parse(现有日志);
                if (!Array.isArray(日志数组)) { 日志数组 = [日志内容]; }
                else if (请求类型 !== "Get_SUB") {
                    const 三十分钟前时间戳 = 当前时间.getTime() - 30 * 60 * 1000;
                    if (日志数组.some(log => log.TYPE !== "Get_SUB" && log.IP === 访问IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= 三十分钟前时间戳)) return;
                    日志数组.push(日志内容);
                    while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
                } else {
                    日志数组.push(日志内容);
                    while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
                }
                if (config_JSON.TG.启用) {
                    try {
                        const TG_TXT = await env.KV.get('tg.json');
                        const TG_JSON = JSON.parse(TG_TXT);
                        await sendMessage(TG_JSON.BotToken, TG_JSON.ChatID, 日志内容, config_JSON);
                    } catch (error) { console.error(`读取tg.json出错: ${error.message}`) }
                }
            } catch (e) { 日志数组 = [日志内容]; }
        } else { 日志数组 = [日志内容]; }
        await env.KV.put('log.json', JSON.stringify(日志数组, null, 2));
    } catch (error) { console.error(`日志记录失败: ${error.message}`); }
}

async function sendMessage(BotToken, ChatID, 日志内容, config_JSON) {
    if (!BotToken || !ChatID) return;

    try {
        const 请求时间 = new Date(日志内容.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        const 请求URL = new URL(日志内容.URL);
        const msg = `<b>#${config_JSON.优选订阅生成.SUBNAME} 日志通知</b>\n\n` +
            `📌 <b>类型：</b>#${日志内容.TYPE}\n` +
            `🌐 <b>IP：</b><code>${日志内容.IP}</code>\n` +
            `📍 <b>位置：</b>${日志内容.CC}\n` +
            `🏢 <b>ASN：</b>${日志内容.ASN}\n` +
            `🔗 <b>域名：</b><code>${请求URL.host}</code>\n` +
            `🔍 <b>路径：</b><code>${请求URL.pathname + 请求URL.search}</code>\n` +
            `🤖 <b>UA：</b><code>${日志内容.UA}</code>\n` +
            `📅 <b>时间：</b>${请求时间}\n` +
            `${config_JSON.CF.Usage.success ? `📊 <b>请求用量：</b>${config_JSON.CF.Usage.total}/100000 <b>${((config_JSON.CF.Usage.total / 100000) * 100).toFixed(2)}%</b>\n` : ''}`;

        const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 日志内容.UA || 'Unknown',
            }
        });
    } catch (error) { console.error('Error sending message:', error) }
}

function 掩码敏感信息(文本, 前缀长度 = 3, 后缀长度 = 2) {
    if (!文本 || typeof 文本 !== 'string') return 文本;
    if (文本.length <= 前缀长度 + 后缀长度) return 文本; // 如果长度太短，直接返回

    const 前缀 = 文本.slice(0, 前缀长度);
    const 后缀 = 文本.slice(-后缀长度);
    const 星号数量 = 文本.length - 前缀长度 - 后缀长度;

    return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

async function MD5MD5(文本) {
    const 编码器 = new TextEncoder();

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
}

function 随机路径() {
    const 常用路径目录 = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "video", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
    const 随机数 = Math.floor(Math.random() * 3 + 1);
    const 随机路径 = 常用路径目录.sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
    return `/${随机路径}`;
}

function 随机替换通配符(h) {
    if (!h?.includes('*')) return h;
    const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
    return h.replace(/\*/g, () => {
        let s = '';
        for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++)
            s += 字符集[Math.floor(Math.random() * 36)];
        return s;
    });
}

function 批量替换域名(内容, hosts, 每组数量 = 2) {
    const 打乱后数组 = [...hosts].sort(() => Math.random() - 0.5);
    let count = 0, currentRandomHost = null;
    return 内容.split(`\n`).map((line, index) => {
        const [host, hash] = 打乱后数组[Math.floor(count / 每组数量) % 打乱后数组.length].split(`#`);
        let replaced = false;
        let newLine = line.replace(/example\.com/g,  (match) => {
            replaced = true;
            count++;
            return 随机替换通配符(host)
        });
        if (replaced) {
            if (newLine.trim().startsWith('- {')) {
                return line.replace(/(name:\s*[^,}]+)/, `$1 - ${hash}`)
            } else {
                newLine += hash ? encodeURIComponent(hash) : ``;
            }
        }
        return newLine
    }).join(`\n`)
}

async function getECH(host) {
    try {
        const res = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=65`, { headers: { 'accept': 'application/dns-json' } });
        const data = await res.json();
        if (!data.Answer?.length) return '';
        for (let ans of data.Answer) {
            if (ans.type !== 65 || !ans.data) continue;
            const match = ans.data.match(/ech=([^\s]+)/);
            if (match) return match[1].replace(/"/g, '');
            if (ans.data.startsWith('\\#')) {
                const hex = ans.data.split(' ').slice(2).join('');
                const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
                let offset = 2;
                while (offset < bytes.length && bytes[offset++] !== 0)
                    offset += bytes[offset - 1];

                while (offset + 4 <= bytes.length) {
                    const key = (bytes[offset] << 8) | bytes[offset + 1];
                    const len = (bytes[offset + 2] << 8) | bytes[offset + 3];
                    offset += 4;

                    if (key === 5) return btoa(String.fromCharCode(...bytes.slice(offset, offset + len)));
                    offset += len;
                }
            }
        }
        return '';
    } catch {
        return '';
    }
}

async function 读取config_JSON(env, hostname, userID, path, 重置配置 = false) {
    //const host = 随机替换通配符(hostname);
    const host = hostname;
    const 初始化开始时间 = performance.now();
    const 默认配置JSON = {
        TIME: new Date().toISOString(),
        HOST: host,
        HOSTS: [hostname],
        UUID: userID,
        协议类型: "v" + "le" + "ss",
        传输协议: "ws",
        跳过证书验证: true,
        启用0RTT: false,
        TLS分片: null,
        随机路径: false,
        ECH: false,
        Fingerprint: "chrome",
        优选订阅生成: {
            local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
            本地IP库: {
                随机IP: true, // 当 随机IP 为true时生效，启用随机IP的数量，否则使用KV内的ADD.txt
                随机数量: 16,
                指定端口: -1,
            },
            SUB: null,
            SUBNAME: "edge" + "tunnel",
            SUBUpdateTime: 3, // 订阅更新时间（小时）
            TOKEN: await MD5MD5(hostname + userID),
        },
        订阅转换配置: {
            SUBAPI: "https://SUBAPI.cmliussss.net",
            SUBCONFIG: "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini",
            SUBEMOJI: false,
        },
        反代: {
            PROXYIP: "auto",
            SOCKS5: {
                启用: 启用SOCKS5反代,
                全局: 启用SOCKS5全局反代,
                账号: 我的SOCKS5账号,
                白名单: SOCKS5白名单,
            },
        },
        TG: {
            启用: false,
            BotToken: null,
            ChatID: null,
        },
        CF: {
            Email: null,
            GlobalAPIKey: null,
            AccountID: null,
            APIToken: null,
            UsageAPI: null,
            Usage: {
                success: false,
                pages: 0,
                workers: 0,
                total: 0,
                max: 100000,
            },
            DoUsage: {
                success: false,
                total: 0,
                max: 13000,
            },
        }
    };

    try {
        let configJSON = await env.KV.get('config.json');
        if (!configJSON || 重置配置 == true) {
            await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
            config_JSON = 默认配置JSON;
        } else {
            config_JSON = JSON.parse(configJSON);
        }
    } catch (error) {
        console.error(`读取config_JSON出错: ${error.message}`);
        config_JSON = 默认配置JSON;
    }

    config_JSON.HOST = host;
    if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
    if (env.HOST) config_JSON.HOSTS = (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
    config_JSON.UUID = userID;
    config_JSON.PATH = path ? (path.startsWith('/') ? path : '/' + path) : (config_JSON.反代.SOCKS5.启用 ? ('/' + config_JSON.反代.SOCKS5.启用 + (config_JSON.反代.SOCKS5.全局 ? '://' : '=') + config_JSON.反代.SOCKS5.账号) : (config_JSON.反代.PROXYIP === 'auto' ? '/' : `/proxyip=${config_JSON.反代.PROXYIP}`));
    const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
    if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
    if (!config_JSON.ECH) config_JSON.ECH = false;
    else config_JSON.优选订阅生成.SUBUpdateTime = 1; // 启用 ECH 时强制将订阅更新时间改为 1 小时
    const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent('cloudflare-ech.com+' + ECH_DOH)}` : '';
    config_JSON.LINK = `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${config_JSON.传输协议 + ECHLINK参数}&host=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&path=${encodeURIComponent(config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
    config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

    const 初始化TG_JSON = { BotToken: null, ChatID: null };
    config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...初始化TG_JSON };
    try {
        const TG_TXT = await env.KV.get('tg.json');
        if (!TG_TXT) {
            await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
        } else {
            const TG_JSON = JSON.parse(TG_TXT);
            config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
            config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
        }
    } catch (error) {
        console.error(`读取tg.json出错: ${error.message}`);
    }

    const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
    config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
    try {
        const CF_TXT = await env.KV.get('cf.json');
        if (!CF_TXT) {
            await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
        } else {
            const CF_JSON = JSON.parse(CF_TXT);
            if (CF_JSON.UsageAPI) {
                try {
                    const response = await fetch(CF_JSON.UsageAPI);
                    const Usage = await response.json();
                    config_JSON.CF.Usage = Usage;
                } catch (err) {
                    console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
                }
            } else {
                config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
                config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
                config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
                config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
                config_JSON.CF.UsageAPI = null;
                const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
                const DoUsage = await getCloudflareDurableObjectsUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, '719b83cf74ac25d1754c4df7d280a64f', '6E0wIOSp0HrvLjioe0UtPlIK_f9pov94XO2YWHqH');
                config_JSON.CF.Usage = Usage;
                config_JSON.CF.DoUsage = DoUsage;
            }
        }
    } catch (error) {
        console.error(`读取cf.json出错: ${error.message}`);
    }

    config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
    return config_JSON;
}

async function 生成随机IP(request, count = 16, 指定端口 = -1) {
    const asnMap = { '9808': 'cmcc', '4837': 'cu', '4134': 'ct' }, asn = request.cf.asn;
    const cidr_url = asnMap[asn] ? `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${asnMap[asn]}.txt` : 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt';
    const cfname = { '9808': 'CF移动优选', '4837': 'CF联通优选', '4134': 'CF电信优选' }[asn] || 'CF官方优选';
    const cfport = [443, 2053, 2083, 2087, 2096, 8443];
    let cidrList = [];
    try { const res = await fetch(cidr_url); cidrList = res.ok ? await 整理成数组(await res.text()) : ['104.16.0.0/13']; } catch { cidrList = ['104.16.0.0/13']; }

    const generateRandomIPFromCIDR = (cidr) => {
        const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
        const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
        const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
        const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
        return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
    };

    const randomIPs = Array.from({ length: count }, () => {
        const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
        return `${ip}:${指定端口 === -1 ? cfport[Math.floor(Math.random() * cfport.length)] : 指定端口}#${cfname}`;
    });
    return [randomIPs, randomIPs.join('\n')];
}

async function 整理成数组(内容) {
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
    const 地址数组 = 替换后的内容.split(',');
    return 地址数组;
}

function isValidBase64(str) {
    if (typeof str !== 'string') return false;
    const cleanStr = str.replace(/\s/g, '');
    if (cleanStr.length === 0 || cleanStr.length % 4 !== 0) return false;
    const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
    if (!base64Regex.test(cleanStr)) return false;
    try {
        atob(cleanStr);
        return true;
    } catch {
        return false;
    }
}

function base64Decode(str) {
    const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
}

async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) {
    if (!urls?.length) return [[], [], []];
    const results = new Set();
    let 订阅链接响应的明文LINK内容 = '', 需要订阅转换订阅URLs = [];
    await Promise.allSettled(urls.map(async (url) => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 超时时间);
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
            let text = '';
            try {
                const buffer = await response.arrayBuffer();
                const contentType = (response.headers.get('content-type') || '').toLowerCase();
                const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

                // 根据 Content-Type 响应头判断编码优先级
                let decoders = ['utf-8', 'gb2312']; // 默认优先 UTF-8
                if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
                    decoders = ['gb2312', 'utf-8']; // 如果明确指定 GB 系编码，优先尝试 GB2312
                }

                // 尝试多种编码解码
                let decodeSuccess = false;
                for (const decoder of decoders) {
                    try {
                        const decoded = new TextDecoder(decoder).decode(buffer);
                        // 验证解码结果的有效性
                        if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
                            text = decoded;
                            decodeSuccess = true;
                            break;
                        } else if (decoded && decoded.length > 0) {
                            // 如果有替换字符 (U+FFFD)，说明编码不匹配，继续尝试下一个编码
                            continue;
                        }
                    } catch (e) {
                        // 该编码解码失败，尝试下一个
                        continue;
                    }
                }

                // 如果所有编码都失败或无效，尝试 response.text()
                if (!decodeSuccess) {
                    text = await response.text();
                }

                // 如果返回的是空或无效数据，返回
                if (!text || text.trim().length === 0) {
                    return;
                }
            } catch (e) {
                console.error('Failed to decode response:', e);
                return;
            }

            // 预处理订阅内容
            /*
            if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox 配置
                需要订阅转换订阅URLs.add(url);
                return;
            }
            */

            const 预处理订阅明文内容 = isValidBase64(text) ? base64Decode(text) : text;
            if (预处理订阅明文内容.split('#')[0].includes('://')) {
                订阅链接响应的明文LINK内容 += 预处理订阅明文内容 + '\n'; // 追加LINK明文内容
                return;
            }

            const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
            const isCSV = lines.length > 1 && lines[0].includes(',');
            const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
            if (!isCSV) {
                lines.forEach(line => {
                    const hashIndex = line.indexOf('#');
                    const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ''];
                    let hasPort = false;
                    if (hostPart.startsWith('[')) {
                        hasPort = /\]:(\d+)$/.test(hostPart);
                    } else {
                        const colonIndex = hostPart.lastIndexOf(':');
                        hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
                    }
                    const port = new URL(url).searchParams.get('port') || 默认端口;
                    results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
                });
            } else {
                const headers = lines[0].split(',').map(h => h.trim());
                const dataLines = lines.slice(1);
                if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
                    const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
                    const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
                        headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
                    const tlsIdx = headers.indexOf('TLS');
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`);
                    });
                } else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
                    const ipIdx = headers.findIndex(h => h.includes('IP'));
                    const delayIdx = headers.findIndex(h => h.includes('延迟'));
                    const speedIdx = headers.findIndex(h => h.includes('下载速度'));
                    const port = new URL(url).searchParams.get('port') || 默认端口;
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`);
                    });
                }
            }
        } catch (e) { }
    }));
    // 将LINK内容转换为数组并去重
    const LINK数组 = 订阅链接响应的明文LINK内容.trim() ? [...new Set(订阅链接响应的明文LINK内容.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
    return [Array.from(results), LINK数组, 需要订阅转换订阅URLs];
}

async function 获取SOCKS5账号(address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];

    // 解析认证
    let username, password;
    if (authPart) {
        [username, password] = authPart.split(":");
        if (!password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
    }

    // 解析主机端口
    let hostname, port;
    if (hostPart.includes("]:")) { // IPv6带端口
        [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))];
    } else if (hostPart.startsWith("[")) { // IPv6无端口
        [hostname, port] = [hostPart, 80];
    } else { // IPv4/域名
        const parts = hostPart.split(":");
        [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80];
    }

    if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');

    return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    const cfg = { "Content-Type": "application/json" };

    try {
        if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

        if (!AccountID) {
            const r = await fetch(`${API}/accounts`, {
                method: "GET",
                headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
            });
            if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
            const d = await r.json();
            if (!d?.result?.length) throw new Error("未找到账户");
            const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
            AccountID = d.result[idx >= 0 ? idx : 0]?.id;
        }

        const now = new Date();
        now.setUTCHours(0, 0, 0, 0);
        const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

        const res = await fetch(`${API}/graphql`, {
            method: "POST",
            headers: hdr,
            body: JSON.stringify({
                query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                    viewer { accounts(filter: {accountTag: $AccountID}) {
                        pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                        workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
                    } }
                }`,
                variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
            })
        });

        if (!res.ok) throw new Error(`查询失败: ${res.status}`);
        const result = await res.json();
        if (result.errors?.length) throw new Error(result.errors[0].message);

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) throw new Error("未找到账户数据");

        const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
        const workers = sum(acc.workersInvocationsAdaptive);
        const total = pages + workers;
        const max = 100000;
        console.log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
        return { success: true, pages, workers, total, max };

    } catch (error) {
        console.error('获取使用量错误:', error.message);
        return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
    }
}

async function getCloudflareDurableObjectsUsage(Email, GlobalAPIKey, AccountID, APIToken) {
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.activeTime || 0), 0) || 0;
    const cfg = { "Content-Type": "application/json" };

    try {
        if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, total: 0, max: 13000 };

        if (!AccountID) {
            const r = await fetch(`${API}/accounts`, {
                method: "GET",
                headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
            });
            if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
            const d = await r.json();
            if (!d?.result?.length) throw new Error("未找到账户");
            const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
            AccountID = d.result[idx >= 0 ? idx : 0]?.id;
        }

        const now = new Date();
        now.setUTCHours(0, 0, 0, 0);
        const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

        const res = await fetch(`${API}/graphql`, {
            method: "POST",
            headers: hdr,
            body: JSON.stringify({
                query: `query getDurableObjectsListQuery($AccountID: string, $filter: ZoneWorkersRequestsFilter_InputObject) {
                          viewer {
                            accounts(filter: {accountTag: $AccountID}) {
                              durableObjectsInvocationsAdaptiveGroups(limit: 10000, filter: $filter) {
                                sum {
                                  errors
                                  requests
                                  responseBodySize
                                  __typename
                                }
                                dimensions {
                                  namespaceId
                                  datetimeHour
                                  __typename
                                }
                                __typename
                              }
                              durableObjectsPeriodicGroups(limit: 10000, filter: $filter) {
                                sum {
                                  activeTime
                                  storageDeletes
                                  storageReadUnits
                                  storageWriteUnits
                                  rowsRead
                                  rowsWritten
                                  __typename
                                }
                                dimensions {
                                  namespaceId
                                  datetimeHour
                                  __typename
                                }
                                __typename
                              }
                              __typename
                            }
                            __typename
                          }
                        }`,
                variables: { AccountID, filter: { datetimeHour_geq: now.toISOString(), datetimeHour_leq: new Date().toISOString() } }
            })
        });

        if (!res.ok) throw new Error(`查询失败: ${res.status}`);
        const result = await res.json();
        if (result.errors?.length) throw new Error(result.errors[0].message);

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) throw new Error("未找到账户数据");
        function ceil2(num) {
            return Math.ceil(num * 100) / 100;
        }
        const total = ceil2(sum(acc.durableObjectsPeriodicGroups)*(128/1024)/1000000);
        const max = 13000 ;
        console.log(`统计结果 - Durable-Objects: ${total}, 上限: ${max}`);
        return { success: true, total, max };

    } catch (error) {
        console.error('获取使用量错误:', error.message);
        return { success: false, total: 0, max: 13000 };
    }
}

async function SOCKS5可用性验证(代理协议 = 'socks5', 代理参数) {
    const startTime = Date.now();
    try { parsedSocks5Address = await 获取SOCKS5账号(代理参数); } catch (err) { return { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime }; }
    const { username, password, hostname, port } = parsedSocks5Address;
    const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
    try {
        const initialData = new Uint8Array(0);
        const tcpSocket = 代理协议 == 'socks5' ? await socks5Connect('check.socks5.090227.xyz', 80, initialData) : await httpConnect('check.socks5.090227.xyz', 80, initialData);
        if (!tcpSocket) return { success: false, error: '无法连接到代理服务器', proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
        try {
            const writer = tcpSocket.writable.getWriter(), encoder = new TextEncoder();
            await writer.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`));
            writer.releaseLock();
            const reader = tcpSocket.readable.getReader(), decoder = new TextDecoder();
            let response = '';
            try { while (true) { const { done, value } = await reader.read(); if (done) break; response += decoder.decode(value, { stream: true }); } } finally { reader.releaseLock(); }
            await tcpSocket.close();
            return { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip: response.match(/ip=(.*)/)[1], loc: response.match(/loc=(.*)/)[1], responseTime: Date.now() - startTime };
        } catch (error) {
            try { await tcpSocket.close(); } catch (e) { console.log('关闭连接时出错:', e); }
            return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
        }
    } catch (error) { return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime }; }
}
//////////////////////////////////////////////////////HTML伪装页面///////////////////////////////////////////////
async function nginx() {
    return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, 访问IP) {
    const now = new Date();
    const 格式化时间戳 = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
    const 随机字符串 = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

    return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${随机字符串} &bull; ${格式化时间戳} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->
    
            <section></section><!-- spacer -->
    
            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>
                    
                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>
                    
                </div>
            </div><!-- /.section -->
    
            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${随机字符串}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${访问IP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>
      
    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};
    
    
  </script> 
</body>
</html>`;
}

