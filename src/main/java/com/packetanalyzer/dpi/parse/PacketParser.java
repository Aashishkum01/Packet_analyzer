package com.packetanalyzer.dpi.parse;

import com.packetanalyzer.dpi.model.ParsedPacket;
import com.packetanalyzer.dpi.model.RawPacket;
import com.packetanalyzer.dpi.util.NetUtil;

public final class PacketParser {
    private PacketParser() {
    }

    public static ParsedPacket parse(RawPacket raw) {
        byte[] data = raw.data();
        if (data.length < 14) {
            return null;
        }

        ParsedPacket parsed = new ParsedPacket();
        parsed.setTimestampSec(raw.header().tsSec());
        parsed.setTimestampUsec(raw.header().tsUsec());
        parsed.setDestMac(macToString(data, 0));
        parsed.setSrcMac(macToString(data, 6));
        parsed.setEtherType(readUint16(data, 12));

        int offset = 14;
        if (parsed.etherType() != NetUtil.ETHER_TYPE_IPV4) {
            parsed.setPayloadOffset(Math.min(offset, data.length));
            parsed.setPayloadLength(Math.max(0, data.length - parsed.payloadOffset()));
            return parsed;
        }

        if (data.length < offset + 20) {
            return null;
        }

        int versionIhl = data[offset] & 0xFF;
        int version = (versionIhl >>> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        int ipHeaderLength = ihl * 4;
        if (version != 4 || ipHeaderLength < 20 || data.length < offset + ipHeaderLength) {
            return null;
        }

        parsed.setHasIp(true);
        parsed.setIpVersion(version);
        parsed.setTtl(data[offset + 8] & 0xFF);
        parsed.setProtocol(data[offset + 9] & 0xFF);
        parsed.setSrcIp(NetUtil.ipv4ToString(data, offset + 12));
        parsed.setDestIp(NetUtil.ipv4ToString(data, offset + 16));
        offset += ipHeaderLength;

        if (parsed.protocol() == NetUtil.PROTOCOL_TCP) {
            if (data.length < offset + 20) {
                return null;
            }
            parsed.setSrcPort(readUint16(data, offset));
            parsed.setDestPort(readUint16(data, offset + 2));
            parsed.setSeqNumber(readUint32(data, offset + 4));
            parsed.setAckNumber(readUint32(data, offset + 8));
            int tcpHeaderLength = ((data[offset + 12] >>> 4) & 0x0F) * 4;
            if (tcpHeaderLength < 20 || data.length < offset + tcpHeaderLength) {
                return null;
            }
            parsed.setHasTcp(true);
            parsed.setTcpFlags(data[offset + 13] & 0xFF);
            offset += tcpHeaderLength;
        } else if (parsed.protocol() == NetUtil.PROTOCOL_UDP) {
            if (data.length < offset + 8) {
                return null;
            }
            parsed.setHasUdp(true);
            parsed.setSrcPort(readUint16(data, offset));
            parsed.setDestPort(readUint16(data, offset + 2));
            offset += 8;
        }

        parsed.setPayloadOffset(Math.min(offset, data.length));
        parsed.setPayloadLength(Math.max(0, data.length - parsed.payloadOffset()));
        return parsed;
    }

    public static String macToString(byte[] data, int offset) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                builder.append(':');
            }
            builder.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return builder.toString();
    }

    private static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static long readUint32(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
            | ((long) (data[offset + 1] & 0xFF) << 16)
            | ((long) (data[offset + 2] & 0xFF) << 8)
            | (data[offset + 3] & 0xFFL);
    }
}
