const net = require('node:net');
const crypto = require('node:crypto');

const jobQueue = [{ job: "send", data: encodeTLS("example.com", 0x16, 0x01), time: Date.now(), timeLog: [] }];
let counter = 0;

main();

async function main() {

    const delayTime = 500;

    const host = "example.com"
    const port = 443;

    const client = net.createConnection({ host, port }, () => {
        console.log(`Connected to ${host}:${port}`);
    });

    client.on('data', async (data) => {

        const nowTime = Date.now();
        const latestJob = jobQueue[jobQueue.length - 1];
        if (latestJob?.job === "decode" && nowTime - latestJob.time < delayTime) {
            jobQueue[jobQueue.length - 1] = {
                job: "decode",
                data: Buffer.concat([latestJob.data, data]),
                time: latestJob.time,
                timeLog: [...latestJob.timeLog, nowTime]
            };
        } else {
            jobQueue.push({
                job: "decode",
                data: data,
                time: nowTime,
                timeLog: [nowTime]
            });
        }
    });

    while (true) {
        await sleep(1000);
        if (jobQueue.length) {
            const job = jobQueue.shift();

            switch (job.job) {
                case "send":
                    client.write(job.data);
                    console.log('Sent data to server.');
                    break;
                case "decode":
                    const decodedData = decodeTLS(job);
                    console.log(decodedData)
                    break;
                default:
                    break;
            }
        }
        counter++;
        console.log(`${Date.now()} [${counter}] | Queue Length: ${jobQueue.length}`);
    }
}

function encodeTLS(host, recordType, handshakeType) {

    // >>> Layer 2: Handshake Protocol
    // Information: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4
    const handshaketype = Buffer.from([handshakeType]); // 0x01 means ClientHello message type
    const body = buildClientHelloPayload(host);
    const bodyLength = toUint24BE(body.length);

    const handshakeMessage = Buffer.concat([
        handshaketype,
        bodyLength,
        body
    ]);

    // >>> Layer 1: TLS Record Protocol
    // Information: https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.1
    const recordtype = Buffer.from([recordType]); // 0x16 means handshake record type
    const version = Buffer.from([0x03, 0x03]);// 0x03 0x03 means TLS 1.2
    const recordLength = toUint16BE(handshakeMessage.length);

    const tlsRecord = Buffer.concat([
        recordtype,
        version,
        recordLength,
        handshakeMessage
    ]);

    return tlsRecord;

}

function decodeTLS(job) {

    const data = job.data;

    // === Process decoding ===
    const record = decodeRecord(data);
    const handshake = decodeHandshake(record.fragment);
    const body = handshake.body;

    return {
        record: record,
        handshake: handshake,
        body: body,
    }

    // === Decoder ===

    // >>> Layer 1: Decode TLS Record Protocol
    function decodeRecord(data) {
        const record = [
            // Layer 1: TLS Record Protocol format
            { name: "contentType", length: 1, value: null },
            { name: "protocolVersion", length: 2, value: null },
            { name: "length", length: 2, value: null },
        ]

        let offset = 0;
        for (const field of record) {
            field.value = data.slice(offset, offset + field.length);
            offset += field.length;
        }

        return {
            contentType: formatRecordType(record[0].value),
            protocolVersion: formatVersion(record[1].value),
            length: toInt(record[2].value),

            // The rest of the data
            fragment: data.slice(offset, offset + toInt(record[2].value))
        };
    };

    // >>> Layer 2: Decode Handshake Protocol
    function decodeHandshake(data) {
        const handshake = [
            // Layer 2: Handshake Protocol format
            { name: "handshakeType", length: 1, value: null },
            { name: "handshakeLength", length: 3, value: null },
        ]

        let offset = 0
        for (const field of handshake) {
            field.value = data.slice(offset, offset + field.length);
            offset += field.length;
        }

        return {
            handshakeType: formatHandshakeType(handshake[0].value),
            handshakeLength: toInt(handshake[1].value),

            // The rest of the data, body
            body: data.slice(offset, offset + toInt(handshake[1].value))
        };
    }

    // === Readable format function

    function formatRecordType(buffer) {
        const value = buffer.readUInt8(0);
        switch (value) {
            case 20: return "ChangeCipherSpec";
            case 14: return "Alert";
            case 22: return "Handshake";
            case 13: return "ApplicationData";
            default: return "Unknown";
        }
    }

    function formatVersion(buffer) {
        const value = buffer.readUInt16BE(0);
        switch (value) {
            case 0x0300: return "SSL 3.0";
            case 0x0301: return "TLS 1.0";
            case 0x0302: return "TLS 1.1";
            case 0x0303: return "TLS 1.2";
            case 0x0304: return "TLS 1.3";
            default: return "Unknown";
        }
    }

    function formatHandshakeType(buffer) {
        const value = buffer.readUInt8(0);
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

function buildClientHelloPayload(targetHost) {

    // >>>>>>>>>>>>>>>>>>>> Payload Structure
    // [2x version]
    // [32x random]
    // [1x sessionIdLength][32x sessionId]
    // [2x cipherSuitesLength][?x cipherSuites]
    // [1x compressionMethodsLength][?x compressionMethods]
    // [2x extensionsLength][?x extensionsPayload]
    // >>>>>>>>>>>>>>>>>>>> Payload Structure


    // === Version ===
    // This value means TLS 1.2, and 0x3 0x3 means it
    const version = [0x03, 0x03];
    const versionBuffer = Buffer.from(version);

    // === Random ===
    // A random 32-byte value generated by the client, used in the later key exchange process
    const random = crypto.randomBytes(32);
    const randomBuffer = Buffer.from(random);

    // === Session ID ===
    // 1 byte length + 32 bytes of random data
    // First byte present the length of the session ID, which is 32 bytes in this case
    // And the rest bytes are just random data
    const sessionIdLength = 32;
    const sessionId = crypto.randomBytes(sessionIdLength);
    const sessionIdBuffer = Buffer.concat([Buffer.from([sessionIdLength]), sessionId]);

    // === Cipher Suites ===
    // This means the cipher suite that client supports.
    // The first 2 bytes mean the length of the cipher suites list, in this case 4 bytes.
    // The rest bytes are the cipher suites ID, the first byte can be acknowledged as the cipher version,
    // and the second byte means the encryption algorithm, detail can be found in the link below
    // https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.5
    const cipherSuites = [
        0x00, 0x3D, // TLS_RSA_WITH_AES_256_CBC_SHA256
        0x00, 0x6B  // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    ];
    const cipherSuitesLength = cipherSuites.length;
    const cipherSuitesLengthBuffer = toUint16BE(cipherSuitesLength);
    const cipherSuitesBuffer = Buffer.concat([
        Buffer.from(cipherSuitesLengthBuffer),
        Buffer.from(cipherSuites)
    ]);

    // === Compression Methods ===
    // This means the compression methods that client supports.
    // The first byte means the length of the compression methods list, in this case 1 byte.
    const compressionMethods = [0x00]; // null compression
    const compressionMethodsLength = compressionMethods.length;
    const compressionMethodsLengthBuffer = toUint8BE(compressionMethodsLength);
    const compressionMethodsBuffer = Buffer.concat([
        Buffer.from(compressionMethodsLengthBuffer),
        Buffer.from(compressionMethods)
    ]);

    // === Extensions ===
    // The first two bytes mean the total length of the extensions, and the rest bytes are the extensions data.
    //Extensions are defined in IANA Transport Layer Security (TLS) 

    // >>> SNI (Server Name Indication) ---
    // This extension is used to indicate the hostname.
    // The row of the bytes means the total data length of the extension, which is
    // type byte (1) + hostname length bytes (2) + hostname bytes (hostname.length)

    const sniExtensionsType = [0x00, 0x00];
    const nameType = [0x00];
    const hostname = targetHost;

    const hostnameBuffer = Buffer.from(hostname);
    const hostnameLength = toUint16BE(hostname.length);

    const serverNameEntry = Buffer.concat([
        Buffer.from(nameType),
        Buffer.from(hostnameLength),
        hostnameBuffer
    ]);

    const sniListLength = toUint16BE(serverNameEntry.length);
    const sniExtensionData = Buffer.concat([
        sniListLength,
        serverNameEntry
    ]);

    const sniExtensionLength = toUint16BE(sniExtensionData.length);
    const sniExtensionBuffer = Buffer.concat([
        Buffer.from(sniExtensionsType),
        Buffer.from(sniExtensionLength),
        sniExtensionData
    ]); // [2x type][2x length][2x listLength][nameType][2x hostnameLength][hostname...]

    // >>> Supported Groups ---
    // This extension is used to indicate the supported groups (elliptic curves) that client supports.
    // The first two bytes mean the total length of the extension, and the rest bytes are the extension data.

    const supportedGroupsExtensionsType = [0x00, 0x0A];
    const supportedGroups = [
        0x00, 0x1D, // x25519
        0x00, 0x17, // secp256r1
        0x00, 0x18  // secp384r1
    ];
    const supportedGroupBufferList = Buffer.from(supportedGroups);
    const supportedGroupsLength = toUint16BE(supportedGroupBufferList.length);
    const supportedGroupData = Buffer.concat([
        supportedGroupsLength,
        supportedGroupBufferList
    ]);

    const supportedGroupsPayloadLength = toUint16BE(supportedGroupData.length);
    const supportedGroupsBuffer = Buffer.concat([
        Buffer.from(supportedGroupsExtensionsType),
        Buffer.from(supportedGroupsPayloadLength),
        supportedGroupData
    ]);//[2x type][2x payloadLength][2x groupLength][supportedGroups...]

    // >>> EC Point Formats ---
    // This extension is used to indicate the supported EC point formats that client supports.
    // The first two bytes mean the total length of the extension, and the rest bytes are the extension data.

    const ecPointFormatsExtensionsType = [0x00, 0x0B];
    const ecPointFormats = [0x00];
    const ecPointFormatsLength = toUint8BE(ecPointFormats.length);
    const ecPointFormatData = Buffer.concat([
        ecPointFormatsLength,
        Buffer.from(ecPointFormats)
    ]);

    const ecPointFormatsPayloadLength = toUint16BE(ecPointFormatData.length);
    const ecPointFormatsBuffer = Buffer.concat([
        Buffer.from(ecPointFormatsExtensionsType),
        Buffer.from(ecPointFormatsPayloadLength),
        ecPointFormatData
    ]);// [2x type][2x payloadLength][1x pointFormatLength][ecPointFormats...]

    // >>> Signature Algorithms ---
    // This extension is used to indicate the supported signature algorithms that client supports.
    // The first two bytes mean the total length of the extension, and the rest bytes are the extension data.

    const signatureAlgorithmsExtensionsType = [0x00, 0x0D];
    const signatureAlgorithms = [
        0x04, 0x03, // ecdsa_secp256r1_sha256
        0x04, 0x01 // rsa_pkcs1_sha256
    ];
    const signatureAlgorithmsLength = toUint16BE(signatureAlgorithms.length);
    const signatureAlgorithmsData = Buffer.concat([
        signatureAlgorithmsLength,
        Buffer.from(signatureAlgorithms)
    ]);

    const signatureAlgorithmsPayloadLength = toUint16BE(signatureAlgorithmsData.length);
    const signatureAlgorithmsBuffer = Buffer.concat([
        Buffer.from(signatureAlgorithmsExtensionsType),
        Buffer.from(signatureAlgorithmsPayloadLength),
        signatureAlgorithmsData
    ]);// [2x type][2x payloadLength][2x signatureAlgorithmsLength][signatureAlgorithms...]

    // ---------

    const extensionsPayload = Buffer.concat([
        sniExtensionBuffer,
        supportedGroupsBuffer,
        ecPointFormatsBuffer,
        signatureAlgorithmsBuffer
    ]);

    const extensionsLength = toUint16BE(extensionsPayload.length);
    const extensionsBuffer = Buffer.concat([
        Buffer.from(extensionsLength),
        extensionsPayload
    ]);// [2x extensionsLength][extensionsPayload...]

    // === Payload ===
    return Buffer.concat([
        versionBuffer,
        randomBuffer,
        sessionIdBuffer,
        cipherSuitesBuffer,
        compressionMethodsBuffer,
        extensionsBuffer
    ]);
}

// Helper functions to convert values to big-endian buffers

function toUint8BE(value) { // One byte placeholder
    const buffer = Buffer.alloc(1);
    buffer.writeUInt8(value, 0);
    return buffer;
}

function toUint16BE(value) { // Two bytes placeholder
    const buffer = Buffer.alloc(2);
    buffer.writeUInt16BE(value, 0);
    return buffer;
}

function toUint24BE(value) { // Three bytes placeholder
    const buffer = Buffer.alloc(3);
    buffer.writeUIntBE(value, 0, 3);
    return buffer;
}

function toUint32BE(value) { // Four bytes placeholder
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value, 0);
    return buffer;
}

function toInt(buffer) {
    const bufferLength = buffer.length;
    return buffer.readUIntBE(0, bufferLength);
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}