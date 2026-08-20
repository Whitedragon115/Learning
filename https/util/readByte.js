module.exports = {
    toInt(buffer) {
        const bufferLength = buffer.length;
        return buffer.readUIntBE(0, bufferLength);
    }
}