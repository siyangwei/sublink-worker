import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, parseBool } from '../../utils.js';

/**
 * Decode Base64-encoded UUID section in non-standard VLESS links.
 * Handles formats like:
 *   auto:UUID, none:UUID, UUID@host:port, or just UUID encoded in Base64.
 *
 * @param {string} uuidPart - The UUID string from URL username section
 * @returns {string} - Decoded UUID or original if not Base64 encoded
 */
function decodeVlessUuid(uuidPart) {
    if (!uuidPart || typeof uuidPart !== 'string') {
        return uuidPart;
    }

    const standardUuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const compactUuidPattern = /^[0-9a-f]{32}$/i;

    let decodedUuid = uuidPart;
    try {
        decodedUuid = decodeURIComponent(uuidPart);
    } catch (e) {
        // Not URL encoded, keep original
    }

    if (standardUuidPattern.test(decodedUuid) || compactUuidPattern.test(decodedUuid)) {
        return decodedUuid;
    }

    if (uuidPart.length < 20 || !/^[A-Za-z0-9+/=]+$/.test(uuidPart)) {
        return uuidPart;
    }

    let base64Decoded;
    try {
        base64Decoded = atob(uuidPart);
    } catch (e) {
        return uuidPart;
    }

    // Pattern: auto:UUID or none:UUID
    if (base64Decoded.startsWith('auto:') || base64Decoded.startsWith('none:')) {
        const uuid = base64Decoded.slice(5);
        if (standardUuidPattern.test(uuid) || compactUuidPattern.test(uuid)) {
            return uuid;
        }
    }

    // Pattern: UUID@host:port (entire connection info encoded)
    if (base64Decoded.includes('@')) {
        const parts = base64Decoded.split('@');
        const uuid = parts[0];
        if (standardUuidPattern.test(uuid) || compactUuidPattern.test(uuid)) {
            return uuid;
        }
    }

    // Pattern: Just UUID
    if (standardUuidPattern.test(base64Decoded) || compactUuidPattern.test(base64Decoded)) {
        return base64Decoded;
    }

    return uuidPart;
}

export function parseVless(url) {
    let { addressPart, params, name } = parseUrlParams(url);

    // Handle non-standard links where entire "prefix:UUID@host:port" is Base64 encoded.
    // e.g., vless://BASE64(none:UUID@host:port)?query#fragment
    if (!addressPart.includes('@')) {
        try {
            const decoded = atob(addressPart);
            if (decoded.includes('@')) {
                addressPart = decoded;
            }
        } catch (e) {
            // Not valid Base64, keep original
        }
    }

    const [uuidRaw, serverInfo] = addressPart.split('@');
    const uuid = decodeVlessUuid(uuidRaw);

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
