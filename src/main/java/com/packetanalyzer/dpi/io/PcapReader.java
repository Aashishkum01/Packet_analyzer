package com.packetanalyzer.dpi.io;

import com.packetanalyzer.dpi.model.PcapGlobalHeader;
import com.packetanalyzer.dpi.model.PcapPacketHeader;
import com.packetanalyzer.dpi.model.RawPacket;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

public final class PcapReader implements Closeable {
    private static final int MAGIC_USEC_LE = 0xA1B2C3D4;
    private static final int MAGIC_USEC_BE = 0xA1B2C3D4;

    private InputStream inputStream;
    private ByteOrder byteOrder;
    private PcapGlobalHeader globalHeader;

    public void open(Path path) throws IOException {
        close();
        inputStream = Files.newInputStream(path);

        byte[] headerBytes = inputStream.readNBytes(24);
        if (headerBytes.length != 24) {
            throw new IOException("Could not read PCAP global header");
        }

        byteOrder = detectOrder(headerBytes);
        ByteBuffer buffer = ByteBuffer.wrap(headerBytes).order(byteOrder);
        globalHeader = new PcapGlobalHeader(
            buffer.getInt(),
            buffer.getShort(),
            buffer.getShort(),
            buffer.getInt(),
            buffer.getInt(),
            buffer.getInt(),
            buffer.getInt()
        );
    }

    public RawPacket readNextPacket() throws IOException {
        ensureOpen();
        byte[] packetHeaderBytes = inputStream.readNBytes(16);
        if (packetHeaderBytes.length == 0) {
            return null;
        }
        if (packetHeaderBytes.length != 16) {
            throw new IOException("Truncated PCAP packet header");
        }

        ByteBuffer headerBuffer = ByteBuffer.wrap(packetHeaderBytes).order(byteOrder);
        PcapPacketHeader packetHeader = new PcapPacketHeader(
            headerBuffer.getInt(),
            headerBuffer.getInt(),
            headerBuffer.getInt(),
            headerBuffer.getInt()
        );

        if (packetHeader.inclLen() < 0 || packetHeader.inclLen() > globalHeader.snapLen() || packetHeader.inclLen() > 65535) {
            throw new IOException("Invalid packet length: " + packetHeader.inclLen());
        }

        byte[] data = inputStream.readNBytes(packetHeader.inclLen());
        if (data.length != packetHeader.inclLen()) {
            throw new IOException("Could not read packet payload");
        }
        return new RawPacket(packetHeader, data);
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public ByteOrder getByteOrder() {
        return byteOrder;
    }

    private void ensureOpen() throws IOException {
        if (inputStream == null || globalHeader == null) {
            throw new IOException("PCAP reader is not open");
        }
    }

    private ByteOrder detectOrder(byte[] headerBytes) throws IOException {
        if ((headerBytes[0] & 0xFF) == 0xD4 && (headerBytes[1] & 0xFF) == 0xC3
            && (headerBytes[2] & 0xFF) == 0xB2 && (headerBytes[3] & 0xFF) == 0xA1) {
            return ByteOrder.LITTLE_ENDIAN;
        }
        if ((headerBytes[0] & 0xFF) == 0xA1 && (headerBytes[1] & 0xFF) == 0xB2
            && (headerBytes[2] & 0xFF) == 0xC3 && (headerBytes[3] & 0xFF) == 0xD4) {
            return ByteOrder.BIG_ENDIAN;
        }
        throw new IOException("Unsupported PCAP magic number");
    }

    @Override
    public void close() throws IOException {
        if (inputStream != null) {
            inputStream.close();
            inputStream = null;
        }
        globalHeader = null;
        byteOrder = null;
    }
}
