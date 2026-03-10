package com.packetanalyzer.dpi.io;

import com.packetanalyzer.dpi.model.PcapGlobalHeader;
import com.packetanalyzer.dpi.model.RawPacket;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

public final class PcapWriter implements Closeable {
    private OutputStream outputStream;
    private ByteOrder byteOrder;

    public void open(Path path, PcapGlobalHeader header, ByteOrder order) throws IOException {
        close();
        outputStream = Files.newOutputStream(path);
        byteOrder = order;
        outputStream.write(header.toBytes(order));
    }

    public synchronized void writePacket(RawPacket packet) throws IOException {
        if (outputStream == null) {
            throw new IOException("PCAP writer is not open");
        }
        outputStream.write(packet.header().toBytes(byteOrder));
        outputStream.write(packet.data());
    }

    @Override
    public void close() throws IOException {
        if (outputStream != null) {
            outputStream.close();
            outputStream = null;
        }
        byteOrder = null;
    }
}
