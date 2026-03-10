package com.packetanalyzer.dpi.model;

public record RawPacket(PcapPacketHeader header, byte[] data) {
}
