package com.packetanalyzer.dpi.engine;

import com.packetanalyzer.dpi.inspect.SniExtractor;
import com.packetanalyzer.dpi.io.PcapReader;
import com.packetanalyzer.dpi.io.PcapWriter;
import com.packetanalyzer.dpi.model.AppType;
import com.packetanalyzer.dpi.model.FiveTuple;
import com.packetanalyzer.dpi.model.ParsedPacket;
import com.packetanalyzer.dpi.model.RawPacket;
import com.packetanalyzer.dpi.parse.PacketParser;
import com.packetanalyzer.dpi.rules.BlockingRules;
import com.packetanalyzer.dpi.util.NetUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class SimpleDpiEngine {
    private final BlockingRules rules;

    public SimpleDpiEngine(BlockingRules rules) {
        this.rules = rules;
    }

    public void process(Path inputFile, Path outputFile) throws IOException {
        try (PcapReader reader = new PcapReader(); PcapWriter writer = new PcapWriter()) {
            reader.open(inputFile);
            writer.open(outputFile, reader.getGlobalHeader(), reader.getByteOrder());

            Map<FiveTuple, Flow> flows = new HashMap<>();
            Map<AppType, Long> appStats = new HashMap<>();
            long totalPackets = 0;
            long forwarded = 0;
            long dropped = 0;

            System.out.println();
            System.out.println("╔══════════════════════════════════════════════════════════════╗");
            System.out.println("║                    DPI ENGINE v1.0                          ║");
            System.out.println("╚══════════════════════════════════════════════════════════════╝");
            System.out.println();
            System.out.println("[DPI] Processing packets...");

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                totalPackets++;

                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null || !parsed.hasIp() || (!parsed.hasTcp() && !parsed.hasUdp())) {
                    continue;
                }

                FiveTuple tuple = new FiveTuple(
                    NetUtil.parseIpv4ToInt(parsed.srcIp()),
                    NetUtil.parseIpv4ToInt(parsed.destIp()),
                    parsed.srcPort(),
                    parsed.destPort(),
                    parsed.protocol()
                );

                Flow flow = flows.computeIfAbsent(tuple, ignored -> new Flow(tuple));
                flow.packets++;
                flow.bytes += raw.data().length;

                classifyFlow(raw, parsed, flow);

                if (!flow.blocked && rules.isBlocked(tuple.srcIp(), flow.appType, flow.sni)) {
                    flow.blocked = true;
                    System.out.print("[BLOCKED] " + parsed.srcIp() + " -> " + parsed.destIp()
                        + " (" + flow.appType.displayName());
                    if (flow.sni != null && !flow.sni.isBlank()) {
                        System.out.print(": " + flow.sni);
                    }
                    System.out.println(")");
                }

                appStats.merge(flow.appType, 1L, Long::sum);

                if (flow.blocked) {
                    dropped++;
                } else {
                    forwarded++;
                    writer.writePacket(raw);
                }
            }

            printReport(totalPackets, forwarded, dropped, flows, appStats);
            System.out.println();
            System.out.println("[Detected Applications/Domains]");
            Map<String, AppType> uniqueSnis = new LinkedHashMap<>();
            for (Flow flow : flows.values()) {
                if (flow.sni != null && !flow.sni.isBlank()) {
                    uniqueSnis.put(flow.sni, flow.appType);
                }
            }
            for (Map.Entry<String, AppType> entry : uniqueSnis.entrySet()) {
                System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().displayName());
            }
            System.out.println();
            System.out.println("Output written to: " + outputFile);
        }
    }

    private void classifyFlow(RawPacket raw, ParsedPacket parsed, Flow flow) {
        byte[] data = raw.data();

        if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS)
            && isUnset(flow.sni) && parsed.hasTcp() && parsed.destPort() == 443 && parsed.payloadLength() > 5) {
            String sni = SniExtractor.extractTlsSni(data, parsed.payloadOffset(), parsed.payloadLength());
            if (sni != null) {
                flow.sni = sni;
                flow.appType = NetUtil.classifyFromSni(sni);
            }
        }

        if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP)
            && isUnset(flow.sni) && parsed.hasTcp() && parsed.destPort() == 80 && parsed.payloadLength() > 0) {
            String host = SniExtractor.extractHttpHost(data, parsed.payloadOffset(), parsed.payloadLength());
            if (host != null) {
                flow.sni = host;
                flow.appType = NetUtil.classifyFromSni(host);
            }
        }

        if (flow.appType == AppType.UNKNOWN && (parsed.destPort() == 53 || parsed.srcPort() == 53)) {
            flow.appType = AppType.DNS;
        }

        if (flow.appType == AppType.UNKNOWN) {
            if (parsed.destPort() == 443) {
                flow.appType = AppType.HTTPS;
            } else if (parsed.destPort() == 80) {
                flow.appType = AppType.HTTP;
            }
        }
    }

    private boolean isUnset(String value) {
        return value == null || value.isBlank();
    }

    private void printReport(
        long totalPackets,
        long forwarded,
        long dropped,
        Map<FiveTuple, Flow> flows,
        Map<AppType, Long> appStats
    ) {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                      ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Total Packets:      %10d                             ║%n", totalPackets);
        System.out.printf("║ Forwarded:          %10d                             ║%n", forwarded);
        System.out.printf("║ Dropped:            %10d                             ║%n", dropped);
        System.out.printf("║ Active Flows:       %10d                             ║%n", flows.size());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                    APPLICATION BREAKDOWN                    ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
        sortedApps.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));
        DecimalFormat percentFormat = new DecimalFormat("0.0");

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = totalPackets == 0 ? 0.0 : (100.0 * entry.getValue() / totalPackets);
            int barLength = (int) (pct / 5);
            String bar = "#".repeat(Math.max(0, barLength));
            System.out.printf("║ %-15s%8d %5s%% %-20s  ║%n",
                entry.getKey().displayName(),
                entry.getValue(),
                percentFormat.format(pct),
                bar);
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    private static final class Flow {
        private final FiveTuple tuple;
        private AppType appType = AppType.UNKNOWN;
        private String sni;
        private long packets;
        private long bytes;
        private boolean blocked;

        private Flow(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }
}
