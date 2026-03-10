package com.packetanalyzer.dpi.model;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public record PcapGlobalHeader(
    int magicNumber,
    short versionMajor,
    short versionMinor,
    int thisZone,
    int sigFigs,
    int snapLen,
    int network
) {
    public byte[] toBytes(ByteOrder order) {
        ByteBuffer buffer = ByteBuffer.allocate(24).order(order);
        buffer.putInt(magicNumber);
        buffer.putShort(versionMajor);
        buffer.putShort(versionMinor);
        buffer.putInt(thisZone);
        buffer.putInt(sigFigs);
        buffer.putInt(snapLen);
        buffer.putInt(network);
        return buffer.array();
    }
}
