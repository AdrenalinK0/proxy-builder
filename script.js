// ===================================================================
// Chain Proxy Builder — script.js
// Parses two proxy URLs and chains them into a full Xray JSON config
// ===================================================================

(function () {
    'use strict';

    // ===== DOM Elements =====
    const config1Input = document.getElementById('config1-input');
    const config2Input = document.getElementById('config2-input');
    const protocol1Tag = document.getElementById('protocol1-tag');
    const protocol2Tag = document.getElementById('protocol2-tag');
    const parsed1 = document.getElementById('parsed1');
    const parsed2 = document.getElementById('parsed2');
    const clear1 = document.getElementById('clear1');
    const clear2 = document.getElementById('clear2');
    const btnGenerate = document.getElementById('btn-generate');
    const generateHint = document.getElementById('generate-hint');
    const outputSection = document.getElementById('output-section');
    const outputJson = document.getElementById('output-json');
    const outputRemark = document.getElementById('output-remark');
    const btnCopy = document.getElementById('btn-copy');
    const btnDownload = document.getElementById('btn-download');
    const flowProxyLabel = document.getElementById('flow-proxy-label');
    const flowChainLabel = document.getElementById('flow-chain-label');
    const config1Card = document.getElementById('config1-card');
    const config2Card = document.getElementById('config2-card');

    let parsedConfig1 = null;
    let parsedConfig2 = null;

    // ===== Base64 Helpers =====
    function safeAtob(str) {
        try {
            const padded = str.replace(/-/g, '+').replace(/_/g, '/');
            const pad = padded.length % 4;
            const final = pad ? padded + '='.repeat(4 - pad) : padded;
            return decodeURIComponent(
                atob(final)
                    .split('')
                    .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                    .join('')
            );
        } catch {
            try {
                const padded = str.replace(/-/g, '+').replace(/_/g, '/');
                const pad = padded.length % 4;
                const final = pad ? padded + '='.repeat(4 - pad) : padded;
                return atob(final);
            } catch {
                return null;
            }
        }
    }

    // ===== URL Parser =====
    function parseProxyURL(raw) {
        const url = raw.trim();
        if (!url) return null;

        if (url.startsWith('vless://')) return parseVless(url);
        if (url.startsWith('vmess://')) return parseVmess(url);
        if (url.startsWith('trojan://')) return parseTrojan(url);
        if (url.startsWith('ss://')) return parseShadowsocks(url);
        if (url.startsWith('socks://') || url.startsWith('socks5://')) return parseSocks(url);
        if (url.startsWith('http://') || url.startsWith('https://')) return parseHttp(url);

        try {
            const decoded = safeAtob(url);
            if (decoded && decoded.includes('"add"')) {
                return parseVmess('vmess://' + url);
            }
        } catch { }

        return { error: 'Unknown protocol. Supported: vless, vmess, trojan, ss, socks, http' };
    }

    function parseVless(url) {
        try {
            const u = new URL(url);
            const params = Object.fromEntries(u.searchParams);
            return {
                protocol: 'vless',
                uuid: u.username || decodeURIComponent(url.split('://')[1].split('@')[0]),
                server: u.hostname,
                port: parseInt(u.port) || 443,
                remark: decodeURIComponent(u.hash.slice(1) || ''),
                type: params.type || 'tcp',
                headerType: params.headerType || 'none',
                host: params.host || undefined,
                path: params.path || undefined,
                serviceName: params.serviceName || undefined,
                authority: params.authority || undefined,
                mode: params.mode || undefined,
                security: params.security || 'none',
                sni: params.sni || undefined,
                fp: params.fp || 'chrome',
                alpn: params.alpn || undefined,
                pbk: params.pbk || undefined,
                sid: params.sid || undefined,
                spx: params.spx || undefined,
                flow: params.flow || undefined,
                encryption: params.encryption || 'none',
                // ECH support
                ech: params.ech || undefined
            };
        } catch (e) {
            return { error: 'Failed to parse VLESS URL: ' + e.message };
        }
    }

    function parseVmess(url) {
        try {
            const b64 = url.replace('vmess://', '');
            const decoded = safeAtob(b64);
            if (!decoded) return { error: 'Failed to decode VMess base64' };
            const config = JSON.parse(decoded);
            return {
                protocol: 'vmess',
                uuid: config.id,
                server: config.add,
                port: parseInt(config.port) || 443,
                aid: parseInt(config.aid) || 0,
                remark: config.ps || '',
                type: config.net || 'tcp',
                headerType: config.type || 'none',
                host: config.host || undefined,
                path: config.path || undefined,
                serviceName: config.path || undefined,
                authority: config.authority || undefined,
                security: config.tls || 'none',
                sni: config.sni || undefined,
                fp: config.fp || 'chrome',
                alpn: config.alpn || undefined
            };
        } catch (e) {
            return { error: 'Failed to parse VMess URL: ' + e.message };
        }
    }

    function parseTrojan(url) {
        try {
            const u = new URL(url);
            const params = Object.fromEntries(u.searchParams);
            return {
                protocol: 'trojan',
                password: decodeURIComponent(u.username || url.split('://')[1].split('@')[0]),
                server: u.hostname,
                port: parseInt(u.port) || 443,
                remark: decodeURIComponent(u.hash.slice(1) || ''),
                type: params.type || 'tcp',
                headerType: params.headerType || 'none',
                host: params.host || undefined,
                path: params.path || undefined,
                serviceName: params.serviceName || undefined,
                authority: params.authority || undefined,
                mode: params.mode || undefined,
                security: params.security || 'tls',
                sni: params.sni || undefined,
                fp: params.fp || 'chrome',
                alpn: params.alpn || undefined,
                pbk: params.pbk || undefined,
                sid: params.sid || undefined,
                spx: params.spx || undefined,
                ech: params.ech || undefined
            };
        } catch (e) {
            return { error: 'Failed to parse Trojan URL: ' + e.message };
        }
    }

    function parseShadowsocks(url) {
        try {
            let raw = url.replace('ss://', '');
            const hashIdx = raw.indexOf('#');
            let remark = '';
            if (hashIdx !== -1) {
                remark = decodeURIComponent(raw.slice(hashIdx + 1));
                raw = raw.slice(0, hashIdx);
            }

            let method, password, server, port;

            if (raw.includes('@')) {
                const [userPart, hostPart] = raw.split('@');
                const decoded = safeAtob(userPart) || userPart;
                const colonIdx = decoded.indexOf(':');
                method = decoded.slice(0, colonIdx);
                password = decoded.slice(colonIdx + 1);
                const hostMatch = hostPart.match(/^(.+):(\d+)/);
                if (hostMatch) {
                    server = hostMatch[1];
                    port = parseInt(hostMatch[2]);
                }
            } else {
                const decoded = safeAtob(raw);
                if (!decoded) return { error: 'Failed to decode SS base64' };
                const match = decoded.match(/^(.+?):(.+)@(.+):(\d+)/);
                if (match) {
                    method = match[1];
                    password = match[2];
                    server = match[3];
                    port = parseInt(match[4]);
                }
            }

            if (!server) return { error: 'Failed to parse Shadowsocks URL' };

            return {
                protocol: 'shadowsocks',
                method: method,
                password: password,
                server: server,
                port: port,
                remark: remark
            };
        } catch (e) {
            return { error: 'Failed to parse Shadowsocks URL: ' + e.message };
        }
    }

    function parseSocks(url) {
        try {
            const u = new URL(url.replace('socks5://', 'socks://').replace('socks://', 'http://'));
            let user, pass;

            if (u.username) {
                const decoded = safeAtob(u.username);
                if (decoded && decoded.includes(':')) {
                    [user, pass] = decoded.split(':');
                } else if (decoded) {
                    user = decoded;
                    pass = u.password ? (safeAtob(u.password) || u.password) : undefined;
                } else {
                    user = decodeURIComponent(u.username);
                    pass = u.password ? decodeURIComponent(u.password) : undefined;
                }
            }

            return {
                protocol: 'socks',
                server: u.hostname,
                port: parseInt(u.port) || 1080,
                user: user || undefined,
                pass: pass || undefined,
                remark: decodeURIComponent(u.hash.slice(1) || '')
            };
        } catch (e) {
            return { error: 'Failed to parse SOCKS URL: ' + e.message };
        }
    }

    function parseHttp(url) {
        try {
            const u = new URL(url);
            let user, pass;

            if (u.username) {
                const decoded = safeAtob(u.username);
                if (decoded && decoded.includes(':')) {
                    [user, pass] = decoded.split(':');
                } else if (decoded) {
                    user = decoded;
                    pass = u.password ? (safeAtob(u.password) || u.password) : undefined;
                } else {
                    user = decodeURIComponent(u.username);
                    pass = u.password ? decodeURIComponent(u.password) : undefined;
                }
            }

            return {
                protocol: 'http',
                server: u.hostname,
                port: parseInt(u.port) || 80,
                user: user || undefined,
                pass: pass || undefined,
                remark: decodeURIComponent(u.hash.slice(1) || '')
            };
        } catch (e) {
            return { error: 'Failed to parse HTTP URL: ' + e.message };
        }
    }

    // ===== Xray Outbound Builders =====

    function buildStreamSettings(params, isChain) {
        const stream = {};
        const netType = params.type || 'tcp';

        // Network
        stream.network = netType;

        // Security
        const security = params.security || 'none';
        stream.security = security;

        // Sockopt
        if (isChain) {
            stream.sockopt = {
                domainStrategy: 'UseIPv4',
                dialerProxy: 'proxy'
            };
        } else {
            stream.sockopt = {
                domainStrategy: 'UseIP'
            };
        }

        // Transport settings — only add when there's actual content
        switch (netType) {
            case 'ws':
                stream.wsSettings = {};
                if (params.host) stream.wsSettings.host = params.host;
                if (params.path) stream.wsSettings.path = params.path;
                if (!params.host && !params.path) stream.wsSettings.path = '/';
                break;

            case 'grpc':
                stream.grpcSettings = {};
                if (params.authority) stream.grpcSettings.authority = params.authority;
                if (params.mode) stream.grpcSettings.multiMode = params.mode === 'multi';
                if (params.serviceName) stream.grpcSettings.serviceName = params.serviceName;
                break;

            case 'httpupgrade':
                stream.httpupgradeSettings = {};
                if (params.host) stream.httpupgradeSettings.host = params.host;
                stream.httpupgradeSettings.path = params.path || '/';
                break;

            case 'tcp':
            case 'raw':
                // Only add rawSettings if headerType is 'http'
                if (params.headerType === 'http') {
                    stream.rawSettings = {
                        header: {
                            type: 'http',
                            request: {
                                headers: {},
                                path: params.path ? params.path.split(',') : ['/'],
                                method: 'GET',
                                version: '1.1'
                            }
                        }
                    };
                    if (params.host) {
                        stream.rawSettings.header.request.headers.Host = params.host.split(',');
                    }
                }
                // For plain TCP (headerType=none), no rawSettings needed
                break;
        }

        // TLS settings
        if (security === 'tls') {
            stream.tlsSettings = {
                serverName: params.sni || params.server,
                fingerprint: params.fp || 'chrome',
                alpn: params.alpn ? params.alpn.split(',') : ['http/1.1'],
                allowInsecure: false
            };
            // ECH support
            if (params.ech) {
                stream.tlsSettings.echConfigList = params.ech;
            }
        } else if (security === 'reality') {
            stream.realitySettings = {
                serverName: params.sni || params.server,
                fingerprint: params.fp || 'chrome',
                publicKey: params.pbk || '',
                shortId: params.sid || '',
                spiderX: params.spx || '',
                show: false,
                allowInsecure: false
            };
        }

        return stream;
    }

    function buildProxyOutbound(params) {
        const streamSettings = buildStreamSettings(params, false);
        const outbound = {
            protocol: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol,
            tag: 'proxy'
        };

        switch (params.protocol) {
            case 'vless':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            encryption: params.encryption || 'none'
                        }]
                    }]
                };
                if (params.flow) outbound.settings.vnext[0].users[0].flow = params.flow;
                break;

            case 'vmess':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            alterId: params.aid || 0,
                            security: 'auto'
                        }]
                    }]
                };
                break;

            case 'trojan':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        password: params.password
                    }]
                };
                break;

            case 'shadowsocks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        method: params.method,
                        password: params.password
                    }]
                };
                break;

            case 'socks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            case 'http':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            default:
                return null;
        }

        outbound.streamSettings = streamSettings;
        return outbound;
    }

    function buildChainOutbound(params) {
        const streamSettings = buildStreamSettings(params, true);
        const outbound = {
            protocol: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol,
            tag: 'chain'
        };

        switch (params.protocol) {
            case 'vless':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            encryption: params.encryption || 'none'
                        }]
                    }]
                };
                break;

            case 'vmess':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            alterId: params.aid || 0,
                            security: 'auto'
                        }]
                    }]
                };
                break;

            case 'trojan':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        password: params.password
                    }]
                };
                break;

            case 'shadowsocks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        method: params.method,
                        password: params.password
                    }]
                };
                break;

            case 'socks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            case 'http':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            default:
                return null;
        }

        outbound.streamSettings = streamSettings;
        return outbound;
    }

    // ===== Full Config Generator =====
    function generateFullConfig(config1, config2) {
        const dnsServer = document.getElementById('dns-server').value;
        const socksPort = parseInt(document.getElementById('socks-port').value) || 10808;
        const logLevel = document.getElementById('log-level').value;

        const proxyOutbound = buildProxyOutbound(config1);
        const chainOutbound = buildChainOutbound(config2);

        if (!proxyOutbound || !chainOutbound) return null;

        const fullConfig = {
            log: {
                loglevel: logLevel
            },
            dns: {
                servers: [
                    {
                        address: dnsServer,
                        tag: 'remote-dns'
                    }
                ],
                queryStrategy: 'UseIP',
                tag: 'dns'
            },
            inbounds: [
                {
                    listen: '127.0.0.1',
                    port: socksPort,
                    protocol: 'socks',
                    settings: {
                        auth: 'noauth',
                        udp: true
                    },
                    tag: 'mixed-in',
                    sniffing: {
                        enabled: true,
                        destOverride: ['http', 'tls']
                    }
                }
            ],
            outbounds: [
                chainOutbound,
                proxyOutbound,
                {
                    protocol: 'dns',
                    tag: 'dns-out'
                },
                {
                    protocol: 'freedom',
                    tag: 'direct',
                    settings: {
                        domainStrategy: 'UseIP'
                    }
                },
                {
                    protocol: 'blackhole',
                    tag: 'block'
                }
            ],
            routing: {
                domainStrategy: 'IPIfNonMatch',
                rules: [
                    {
                        inboundTag: ['remote-dns'],
                        outboundTag: 'proxy',
                        type: 'field'
                    },
                    {
                        network: 'tcp',
                        outboundTag: 'chain',
                        type: 'field'
                    },
                    {
                        protocol: ['dns'],
                        outboundTag: 'dns-out',
                        type: 'field'
                    }
                ]
            }
        };

        const remark = `🔗 ${config1.protocol.toUpperCase()} → ${config2.protocol.toUpperCase()} | ${config2.server}:${config2.port}`;
        return { config: fullConfig, remark };
    }

    // ===== UI Render Helpers =====
    function renderParsedInfo(params, container) {
        if (!params || params.error) {
            container.innerHTML = params
                ? `<div class="error-msg">⚠️ ${params.error}</div>`
                : '';
            return;
        }

        const rows = [];
        rows.push(['Protocol', params.protocol.toUpperCase()]);
        rows.push(['Server', params.server]);
        rows.push(['Port', params.port]);

        if (params.uuid) rows.push(['UUID', params.uuid]);
        if (params.password) rows.push(['Password', maskString(params.password)]);
        if (params.method) rows.push(['Method', params.method]);
        if (params.user) rows.push(['User', params.user]);
        if (params.type && params.type !== 'tcp') rows.push(['Transport', params.type]);
        if (params.security && params.security !== 'none') rows.push(['Security', params.security]);
        if (params.sni) rows.push(['SNI', params.sni]);
        if (params.host) rows.push(['Host', params.host]);
        if (params.path) rows.push(['Path', truncateStr(params.path, 50)]);
        if (params.ech) rows.push(['ECH', '✅ Enabled']);
        if (params.remark) rows.push(['Remark', params.remark]);

        container.innerHTML = rows.map(([label, value]) =>
            `<div class="info-row">
                <span class="info-label">${label}</span>
                <span class="info-value">${escapeHtml(String(value))}</span>
            </div>`
        ).join('');
    }

    function maskString(str) {
        if (!str || str.length <= 8) return str;
        return str.slice(0, 4) + '••••' + str.slice(-4);
    }

    function truncateStr(str, max) {
        if (!str || str.length <= max) return str;
        return str.slice(0, max) + '…';
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function getProtocolColor(protocol) {
        const colors = {
            vless: '#7c5cff',
            vmess: '#5c8cff',
            trojan: '#f05050',
            shadowsocks: '#3cd4f0',
            socks: '#4cdf86',
            http: '#f0c040'
        };
        return colors[protocol] || '#9090b0';
    }

    function updateProtocolTag(tag, protocol) {
        if (protocol && !protocol.error) {
            tag.textContent = protocol.protocol.toUpperCase();
            tag.classList.add('active');
            tag.style.color = getProtocolColor(protocol.protocol);
            tag.style.borderColor = getProtocolColor(protocol.protocol) + '4d';
            tag.style.background = getProtocolColor(protocol.protocol) + '1a';
        } else {
            tag.textContent = '—';
            tag.classList.remove('active');
            tag.style.color = '';
            tag.style.borderColor = '';
            tag.style.background = '';
        }
    }

    // ===== JSON Syntax Highlighting =====
    function highlightJSON(json) {
        const str = JSON.stringify(json, null, 2);
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"([^"]+)"(?=\s*:)/g, '<span class="json-key">"$1"</span>')
            .replace(/:\s*"([^"]*)"/g, ': <span class="json-string">"$1"</span>')
            .replace(/:\s*(\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
            .replace(/:\s*(true|false)/g, ': <span class="json-boolean">$1</span>')
            .replace(/:\s*(null)/g, ': <span class="json-null">$1</span>')
            .replace(/([{}[\]])/g, '<span class="json-brace">$1</span>');
    }

    // ===== Event Handlers =====
    function onInputChange(inputEl, parsedContainer, protocolTag, card, isConfig1) {
        const val = inputEl.value.trim();
        const parsed = val ? parseProxyURL(val) : null;

        if (isConfig1) {
            parsedConfig1 = parsed && !parsed.error ? parsed : null;
        } else {
            parsedConfig2 = parsed && !parsed.error ? parsed : null;
        }

        renderParsedInfo(parsed, parsedContainer);
        updateProtocolTag(protocolTag, parsed);

        card.classList.remove('valid', 'invalid');
        if (val && parsed) {
            card.classList.add(parsed.error ? 'invalid' : 'valid');
        }

        if (isConfig1 && parsedConfig1) {
            flowProxyLabel.textContent = `${parsedConfig1.protocol.toUpperCase()} ${parsedConfig1.server}`;
        } else if (isConfig1) {
            flowProxyLabel.textContent = 'Config 1';
        }

        if (!isConfig1 && parsedConfig2) {
            flowChainLabel.textContent = `${parsedConfig2.protocol.toUpperCase()} ${parsedConfig2.server}`;
        } else if (!isConfig1) {
            flowChainLabel.textContent = 'Config 2';
        }

        updateGenerateButton();
    }

    function updateGenerateButton() {
        const enabled = parsedConfig1 && parsedConfig2;
        btnGenerate.disabled = !enabled;
        generateHint.textContent = enabled
            ? 'Ready to generate!'
            : (!parsedConfig1 && !parsedConfig2)
                ? 'Paste both configs above to enable'
                : !parsedConfig1
                    ? 'Config 1 is missing or invalid'
                    : 'Config 2 is missing or invalid';
        generateHint.style.color = enabled ? '#4cdf86' : '';
    }

    function onGenerate() {
        if (!parsedConfig1 || !parsedConfig2) return;

        const result = generateFullConfig(parsedConfig1, parsedConfig2);
        if (!result) {
            outputSection.style.display = 'none';
            return;
        }

        outputRemark.textContent = result.remark;
        outputJson.innerHTML = highlightJSON(result.config);
        outputSection.style.display = 'block';
        outputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function onCopy() {
        if (!parsedConfig1 || !parsedConfig2) return;
        const result = generateFullConfig(parsedConfig1, parsedConfig2);
        if (!result) return;

        const text = JSON.stringify(result.config, null, 2);
        navigator.clipboard.writeText(text).then(() => {
            btnCopy.classList.add('copied');
            btnCopy.innerHTML = '<span class="copy-icon">✅</span> Copied!';
            setTimeout(() => {
                btnCopy.classList.remove('copied');
                btnCopy.innerHTML = '<span class="copy-icon">📋</span> Copy';
            }, 2000);
        });
    }

    function onDownload() {
        if (!parsedConfig1 || !parsedConfig2) return;
        const result = generateFullConfig(parsedConfig1, parsedConfig2);
        if (!result) return;

        const text = JSON.stringify(result.config, null, 2);
        const blob = new Blob([text], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `chain-${parsedConfig1.protocol}-${parsedConfig2.protocol}-${parsedConfig2.server}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ===== Wire Events =====
    config1Input.addEventListener('input', () =>
        onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true));
    config2Input.addEventListener('input', () =>
        onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false));
    config1Input.addEventListener('paste', () =>
        setTimeout(() => onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true), 50));
    config2Input.addEventListener('paste', () =>
        setTimeout(() => onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false), 50));

    clear1.addEventListener('click', () => {
        config1Input.value = '';
        onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true);
    });
    clear2.addEventListener('click', () => {
        config2Input.value = '';
        onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false);
    });

    btnGenerate.addEventListener('click', onGenerate);
    btnCopy.addEventListener('click', onCopy);
    btnDownload.addEventListener('click', onDownload);
})();
