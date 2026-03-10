package com.packetanalyzer.dpi.model;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public record PcapPacketHeader(
    int tsSec,
    int tsUsec,
    int inclLen,
    int origLen
) {
    public byte[] toBytes(ByteOrder order) {
        ByteBuffer buffer = ByteBuffer.allocate(16).order(order);
        buffer.putInt(tsSec);
        buffer.putInt(tsUsec);
        buffer.putInt(inclLen);
        buffer.putInt(origLen);
        return buffer.array();
    }
}
