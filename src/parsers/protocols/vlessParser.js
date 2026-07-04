import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, parseBool } from '../../utils.js';

/**
 * Decode Base64-encoded UUID section in non-standard VLESS links
 * Handles formats like:
 *   vless://YXV0bzpVVUlE@host:port?... (decodes to auto:UUID)
 *   vless://VVVJREBob3N0OnBvcnQ=... (decodes to UUID@host:port)
 *   vless://VVVJRA==@host:port?... (decodes to UUID)
 * 
 * @param {string} uuidPart - The UUID string from URL username section
 * @returns {string} - Decoded UUID or original if not Base64 encoded
 */
function decodeVlessUuid(uuidPart) {
    if (!uuidPart || typeof uuidPart !== 'string') {
        return uuidPart;
    }

    // Already standard UUID format (with or without dashes, or with URL encoding)
    // Standard UUID: 8-4-4-4-12 hex format
    const standardUuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const compactUuidPattern = /^[0-9a-f]{32}$/i;
    
    // URL decode first if needed
    let decodedUuid = uuidPart;
    try {
        decodedUuid = decodeURIComponent(uuidPart);
    } catch (e) {
        // Not URL encoded, keep original
    }

    // Check if already standard format
    if (standardUuidPattern.test(decodedUuid) || compactUuidPattern.test(decodedUuid)) {
        return decodedUuid;
    }

    // Check if looks like Base64 (long enough, only Base64 chars)
    if (uuidPart.length < 20 || !/^[A-Za-z0-9+/=]+$/.test(uuidPart)) {
        return uuidPart;
    }

    // Try Base64 decode
    let base64Decoded;
    try {
        base64Decoded = atob(uuidPart);
    } catch (e) {
        return uuidPart; // Not valid Base64
    }

    // Pattern 1: auto:UUID
    if (base64Decoded.startsWith('auto:')) {
        const uuid = base64Decoded.slice(5); // Remove 'auto:' prefix
        if (standardUuidPattern.test(uuid) || compactUuidPattern.test(uuid)) {
            return uuid;
        }
    }

    // Pattern 2: UUID@host:port (entire connection info encoded)
    if (base64Decoded.includes('@')) {
        const parts = base64Decoded.split('@');
        const uuid = parts[0];
        if (standardUuidPattern.test(uuid) || compactUuidPattern.test(uuid)) {
            return uuid;
        }
    }

    // Pattern 3: Just UUID (only UUID encoded in Base64)
    if (standardUuidPattern.test(base64Decoded) || compactUuidPattern.test(base64Decoded)) {
        return base64Decoded;
    }

    // None matched, return original
    return uuidPart;
}

export function parseVless(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const [uuidRaw, serverInfo] = addressPart.split('@');
    
    // Decode non-standard Base64-encoded UUID
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