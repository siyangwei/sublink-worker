import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, parseBool } from '../../utils.js';

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function tryBase64Decode(s) {
    try {
        return atob(s);
    } catch (e) {
        return null;
    }
}

export function parseVless(url) {
    let { addressPart, params, name } = parseUrlParams(url);

    // iOS Shadowrocket exports the entire "prefix:UUID@host:port" section as Base64.
    // Try to decode it first so standard parsing can take over.
    if (!addressPart.includes('@')) {
        const decoded = tryBase64Decode(addressPart);
        if (decoded && decoded.includes('@')) {
            addressPart = decoded;
        }
    }

    const [rawUuid, serverInfo] = addressPart.split('@');
    // Strip iOS Shadowrocket's "auto:" / "none:" prefix from the decoded username.
    const uuid = rawUuid.replace(/^(auto|none):/i, '');
    const { host, port } = parseServerInfo(serverInfo);

    const tls = createTlsConfig(params);
    if (tls.reality) {
        tls.utls = {
            enabled: true,
            fingerprint: 'chrome'
        };
    }
    const transport = params.type !== 'tcp' ? createTransportConfig(params) : undefined;

    // `udp` is a Clash-only flag; ClashConfigBuilder reads it, SingboxConfigBuilder strips it.
    const udp = params.udp !== undefined ? parseBool(params.udp) : undefined;

    // iOS Shadowrocket puts the node name in query params (remarks) instead of URL hash.
    const tag = name || params.remarks || params.remark || '';

    return {
        type: 'vless',
        tag,
        server: host,
        server_port: port,
        uuid: uuid,
        tcp_fast_open: false,
        tls,
        transport,
        flow: params.flow ?? undefined,
        ...(udp !== undefined ? { udp } : {})
    };
}
