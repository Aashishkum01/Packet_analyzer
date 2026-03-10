package com.packetanalyzer.dpi.cli;

import com.packetanalyzer.dpi.engine.MultithreadedDpiEngine;
import com.packetanalyzer.dpi.rules.BlockingRules;

import java.nio.file.Path;

public final class MultithreadedDpiCli {
    private MultithreadedDpiCli() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        int lbs = 2;
        int fps = 2;
        BlockingRules rules = new BlockingRules();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if ("--block-ip".equals(arg) && i + 1 < args.length) {
                rules.blockIp(args[++i]);
            } else if ("--block-app".equals(arg) && i + 1 < args.length) {
                rules.blockApp(args[++i]);
            } else if ("--block-domain".equals(arg) && i + 1 < args.length) {
                rules.blockDomain(args[++i]);
            } else if ("--lbs".equals(arg) && i + 1 < args.length) {
                lbs = Integer.parseInt(args[++i]);
            } else if ("--fps".equals(arg) && i + 1 < args.length) {
                fps = Integer.parseInt(args[++i]);
            }
        }

        MultithreadedDpiEngine engine = new MultithreadedDpiEngine(
            new MultithreadedDpiEngine.Config(lbs, fps),
            rules
        );
        engine.process(Path.of(args[0]), Path.of(args[1]));
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("DPI Engine v2.0 - Multi-threaded Deep Packet Inspection");
        System.out.println("========================================================");
        System.out.println();
        System.out.println("Usage: java ... MultithreadedDpiCli <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block source IP");
        System.out.println("  --block-app <app>      Block application");
        System.out.println("  --block-domain <dom>   Block domain");
        System.out.println("  --lbs <n>              Number of load balancer threads (default: 2)");
        System.out.println("  --fps <n>              FP threads per LB (default: 2)");
    }
}
