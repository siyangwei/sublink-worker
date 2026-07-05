import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, parseBool } from '../../utils.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const COMPACT_UUID_RE = /^[0-9a-f]{32}$/i;
const UUID_IN_STRING_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function isBase64Like(s) {
    return s.length >= 20 && /^[A-Za-z0-9+/=]+$/.test(s);
}

function tryBase64Decode(s) {
    try {
        return atob(s);
    } catch (e) {
        return null;
    }
}

/**
 * Decode non-standard UUID part: auto:UUID, none:UUID, compact UUID, or Base64 UUID.
 *
 * @param {string} uuidPart - The UUID string from URL username section
 * @returns {string} - Decoded UUID or original if not recognized
 */
function decodeVlessUuid(uuidPart) {
    if (!uuidPart || typeof uuidPart !== 'string') {
        return uuidPart;
    }

    let decoded = uuidPart;
    try {
        decoded = decodeURIComponent(uuidPart);
    } catch (e) {
        // Not URL encoded, keep original
    }

    if (UUID_RE.test(decoded) || COMPACT_UUID_RE.test(decoded)) {
        return decoded;
    }

    if (isBase64Like(uuidPart)) {
        const base64Decoded = tryBase64Decode(uuidPart);
        if (base64Decoded) {
            // auto:UUID or none:UUID
            if (base64Decoded.startsWith('auto:') || base64Decoded.startsWith('none:')) {
                const uuid = base64Decoded.slice(5);
                if (UUID_RE.test(uuid) || COMPACT_UUID_RE.test(uuid)) {
                    return uuid;
                }
            }
            // Just UUID
            if (UUID_RE.test(base64Decoded) || COMPACT_UUID_RE.test(base64Decoded)) {
                return base64Decoded;
            }
        }
    }

    return uuidPart;
}

export function parseVless(url) {
    let { addressPart, params, name } = parseUrlParams(url);

    let uuid = null;
    let serverInfo = null;

    // Non-standard: entire "prefix:UUID@host:port" is Base64 encoded (iOS Shadowrocket export).
    // e.g., vless://BASE64(none:UUID@host:port)?query#fragment
    if (!addressPart.includes('@') && isBase64Like(addressPart)) {
        const decoded = tryBase64Decode(addressPart);
        if (decoded) {
            const match = decoded.match(UUID_IN_STRING_RE);
            if (match) {
                uuid = match[0].toLowerCase();
                const afterUuid = decoded.slice(match.index + match[0].length).replace(/^@/, '');
                if (afterUuid.includes(':')) {
                    serverInfo = afterUuid;
                }
            }
        }
    }

    // Standard format: UUID@host:port, or fallback
    if (!uuid) {
        const parts = addressPart.split('@');
        uuid = decodeVlessUuid(parts[0]);
        serverInfo = parts[1];
    }

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

    return {
        type: 'vless',
        tag: name,
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
