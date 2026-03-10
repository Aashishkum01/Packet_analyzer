package com.packetanalyzer.dpi.cli;

import com.packetanalyzer.dpi.engine.SimpleDpiEngine;
import com.packetanalyzer.dpi.rules.BlockingRules;

import java.nio.file.Path;

public final class SimpleDpiCli {
    private SimpleDpiCli() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        BlockingRules rules = new BlockingRules();
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if ("--block-ip".equals(arg) && i + 1 < args.length) {
                rules.blockIp(args[++i]);
            } else if ("--block-app".equals(arg) && i + 1 < args.length) {
                rules.blockApp(args[++i]);
            } else if ("--block-domain".equals(arg) && i + 1 < args.length) {
                rules.blockDomain(args[++i]);
            }
        }

        SimpleDpiEngine engine = new SimpleDpiEngine(rules);
        engine.process(Path.of(args[0]), Path.of(args[1]));
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("DPI Engine - Deep Packet Inspection System");
        System.out.println("==========================================");
        System.out.println();
        System.out.println("Usage: java ... SimpleDpiCli <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block traffic from source IP");
        System.out.println("  --block-app <app>      Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <dom>   Block domain (substring match)");
    }
}
