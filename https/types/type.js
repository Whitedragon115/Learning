const { toInt } = require('../util/readByte');

module.exports = {

    cipherSuiteType(data) {
        const value = toInt(data);

        // Information: https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.5
        switch (value) {
            case 0x0001: return "TLS_RSA_WITH_NULL_MD5";
            case 0x0002: return "TLS_RSA_WITH_NULL_SHA";
            case 0x003B: return "TLS_RSA_WITH_NULL_SHA256";
            case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5";
            case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA";
            case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
            case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
            case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
            case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
            case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
            case 0x000D: return "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
            case 0x0010: return "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
            case 0x0013: return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
            case 0x0016: return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
            case 0x0030: return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
            case 0x0031: return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
            case 0x0032: return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
            case 0x0033: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
            case 0x0036: return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
            case 0x0037: return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
            case 0x0038: return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
            case 0x0039: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
            case 0x003E: return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
            case 0x003F: return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
            case 0x0040: return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
            case 0x0067: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
            case 0x0068: return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
            case 0x0069: return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
            case 0x006A: return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
            case 0x006B: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
            case 0x0018: return "TLS_DH_anon_WITH_RC4_128_MD5";
            case 0x001B: return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
            case 0x0034: return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
            case 0x003A: return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
            case 0x006C: return "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
            case 0x006D: return "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
            default: return "Unknown";
        }
    },

    formatRecordType(buffer) {
        const value = buffer.readUInt8(0);
        switch (value) {
            case 20: return "ChangeCipherSpec";
            case 14: return "Alert";
            case 22: return "Handshake";
            case 13: return "ApplicationData";
            default: return "Unknown";
        }
    },

    protocolVersion(buffer) {
        const value = buffer.readUInt16BE(0);
        switch (value) {
            case 0x0300: return "SSL 3.0";
            case 0x0301: return "TLS 1.0";
            case 0x0302: return "TLS 1.1";
            case 0x0303: return "TLS 1.2";
            case 0x0304: return "TLS 1.3";
            default: return "Unknown";
        }
    },

    formatHandshakeType(buffer) {
        const value = buffer.readUInt8(0);

        // Information: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4
        switch (value) {
            case 0: return "HelloRequest";
            case 1: return "ClientHello";
            case 2: return "ServerHello";
            case 11: return "Certificate";
            case 12: return "ServerKeyExchange";
            case 13: return "CertificateRequest";
            case 14: return "ServerHelloDone";
            case 15: return "CertificateVerify";
            case 16: return "ClientKeyExchange";
            case 20: return "Finished";
            default: return "Unknown";
        }
    }

}
