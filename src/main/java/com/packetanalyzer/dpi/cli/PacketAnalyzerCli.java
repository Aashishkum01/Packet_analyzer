package com.packetanalyzer.dpi.cli;

import com.packetanalyzer.dpi.io.PcapReader;
import com.packetanalyzer.dpi.model.ParsedPacket;
import com.packetanalyzer.dpi.model.RawPacket;
import com.packetanalyzer.dpi.parse.PacketParser;
import com.packetanalyzer.dpi.util.NetUtil;

import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class PacketAnalyzerCli {
    private PacketAnalyzerCli() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0");
        System.out.println("====================================");
        System.out.println();

        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        Path file = Path.of(args[0]);
        int maxPackets = args.length >= 2 ? Integer.parseInt(args[1]) : -1;

        int packetCount = 0;
        int parseErrors = 0;

        try (PcapReader reader = new PcapReader()) {
            reader.open(file);
            System.out.println("--- Reading packets ---");

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                packetCount++;
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                } else {
                    printPacketSummary(parsed, raw, packetCount);
                }

                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println();
                    System.out.println("(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }
        }

        System.out.println();
        System.out.println("====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read:  " + packetCount);
        System.out.println("  Parse errors:        " + parseErrors);
        System.out.println("====================================");
    }

    private static void printUsage() {
        System.out.println("Usage: java ... PacketAnalyzerCli <pcap_file> [max_packets]");
    }

    private static void printPacketSummary(ParsedPacket packet, RawPacket raw, int packetNum) {
        Instant instant = Instant.ofEpochSecond(packet.timestampSec(), packet.timestampUsec() * 1_000L);
        String formattedTime = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault())
            .format(instant);

        System.out.println();
        System.out.println("========== Packet #" + packetNum + " ==========");
        System.out.println("Time: " + formattedTime + "." + String.format("%06d", packet.timestampUsec()));
        System.out.println();
        System.out.println("[Ethernet]");
        System.out.println("  Source MAC:      " + packet.srcMac());
        System.out.println("  Destination MAC: " + packet.destMac());
        System.out.print("  EtherType:       0x" + String.format("%04x", packet.etherType()));
        if (packet.etherType() == NetUtil.ETHER_TYPE_IPV4) {
            System.out.print(" (IPv4)");
        } else if (packet.etherType() == NetUtil.ETHER_TYPE_IPV6) {
            System.out.print(" (IPv6)");
        } else if (packet.etherType() == NetUtil.ETHER_TYPE_ARP) {
            System.out.print(" (ARP)");
        }
        System.out.println();

        if (packet.hasIp()) {
            System.out.println();
            System.out.println("[IPv" + packet.ipVersion() + "]");
            System.out.println("  Source IP:      " + packet.srcIp());
            System.out.println("  Destination IP: " + packet.destIp());
            System.out.println("  Protocol:       " + NetUtil.protocolToString(packet.protocol()));
            System.out.println("  TTL:            " + packet.ttl());
        }

        if (packet.hasTcp()) {
            System.out.println();
            System.out.println("[TCP]");
            System.out.println("  Source Port:      " + packet.srcPort());
            System.out.println("  Destination Port: " + packet.destPort());
            System.out.println("  Sequence Number:  " + packet.seqNumber());
            System.out.println("  Ack Number:       " + packet.ackNumber());
            System.out.println("  Flags:            " + NetUtil.tcpFlagsToString(packet.tcpFlags()));
        }

        if (packet.hasUdp()) {
            System.out.println();
            System.out.println("[UDP]");
            System.out.println("  Source Port:      " + packet.srcPort());
            System.out.println("  Destination Port: " + packet.destPort());
        }

        if (packet.payloadLength() > 0) {
            System.out.println();
            System.out.println("[Payload]");
            System.out.println("  Length: " + packet.payloadLength() + " bytes");
            System.out.print("  Preview: ");
            int previewLength = Math.min(packet.payloadLength(), 32);
            byte[] data = raw.data();
            for (int i = 0; i < previewLength; i++) {
                System.out.print(String.format("%02x ", data[packet.payloadOffset() + i] & 0xFF));
            }
            if (packet.payloadLength() > 32) {
                System.out.print("...");
            }
            System.out.println();
        }
    }
}
