module.exports = {
    toUint8BE: function (value) { // One byte placeholder
        const buffer = Buffer.alloc(1);
        buffer.writeUInt8(value, 0);
        return buffer;
    },

    toUint16BE: function (value) { // Two bytes placeholder
        const buffer = Buffer.alloc(2);
        buffer.writeUInt16BE(value, 0);
        return buffer;
    },

    toUint24BE: function (value) { // Three bytes placeholder
        const buffer = Buffer.alloc(3);
        buffer.writeUIntBE(value, 0, 3);
        return buffer;
    },

    toUint32BE: function (value) { // Four bytes placeholder
        const buffer = Buffer.alloc(4);
        buffer.writeUInt32BE(value, 0);
        return buffer;
    }
}