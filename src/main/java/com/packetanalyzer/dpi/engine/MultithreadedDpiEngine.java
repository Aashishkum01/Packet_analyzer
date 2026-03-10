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
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class MultithreadedDpiEngine {
    public record Config(int numLoadBalancers, int fpsPerLoadBalancer) {
    }

    private static final PacketJob POISON_PACKET = new PacketJob(-1, null, null, 0, 0, 0, 0);

    private final Config config;
    private final BlockingRules rules;
    private final Stats stats = new Stats();
    private final BlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10_000);
    private final List<FastPathWorker> fastPaths = new ArrayList<>();
    private final List<LoadBalancerWorker> loadBalancers = new ArrayList<>();

    public MultithreadedDpiEngine(Config config, BlockingRules rules) {
        this.config = config;
        this.rules = rules;

        for (int i = 0; i < config.numLoadBalancers() * config.fpsPerLoadBalancer(); i++) {
            fastPaths.add(new FastPathWorker(i));
        }

        for (int lb = 0; lb < config.numLoadBalancers(); lb++) {
            List<FastPathWorker> workers = new ArrayList<>();
            int start = lb * config.fpsPerLoadBalancer();
            for (int i = 0; i < config.fpsPerLoadBalancer(); i++) {
                workers.add(fastPaths.get(start + i));
            }
            loadBalancers.add(new LoadBalancerWorker(lb, workers));
        }
    }

    public void process(Path inputFile, Path outputFile) throws IOException, InterruptedException {
        try (PcapReader reader = new PcapReader(); PcapWriter writer = new PcapWriter()) {
            reader.open(inputFile);
            writer.open(outputFile, reader.getGlobalHeader(), reader.getByteOrder());

            printBanner();

            for (FastPathWorker fastPath : fastPaths) {
                fastPath.start();
            }
            for (LoadBalancerWorker loadBalancer : loadBalancers) {
                loadBalancer.start();
            }

            AtomicBoolean outputRunning = new AtomicBoolean(true);
            Thread outputThread = new Thread(() -> {
                try {
                    while (outputRunning.get() || !outputQueue.isEmpty()) {
                        PacketJob job = outputQueue.poll();
                        if (job == null || job == POISON_PACKET) {
                            Thread.sleep(10);
                            continue;
                        }
                        writer.writePacket(job.rawPacket());
                    }
                } catch (IOException | InterruptedException exception) {
                    throw new RuntimeException(exception);
                }
            }, "output-writer");
            outputThread.start();

            System.out.println("[Reader] Processing packets...");
            int packetId = 0;
            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
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
                PacketJob job = new PacketJob(packetId++, tuple, raw, parsed.payloadOffset(), parsed.payloadLength(), parsed.tcpFlags(), parsed.protocol());

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data().length);
                if (parsed.hasTcp()) {
                    stats.tcpPackets.incrementAndGet();
                } else if (parsed.hasUdp()) {
                    stats.udpPackets.incrementAndGet();
                }

                loadBalancers.get(Math.floorMod(tuple.hashCode(), loadBalancers.size())).queue.put(job);
            }

            System.out.println("[Reader] Done reading " + packetId + " packets");

            for (LoadBalancerWorker loadBalancer : loadBalancers) {
                loadBalancer.queue.put(POISON_PACKET);
            }
            for (LoadBalancerWorker loadBalancer : loadBalancers) {
                loadBalancer.join();
            }

            for (FastPathWorker fastPath : fastPaths) {
                fastPath.queue.put(POISON_PACKET);
            }
            for (FastPathWorker fastPath : fastPaths) {
                fastPath.join();
            }

            outputRunning.set(false);
            outputQueue.put(POISON_PACKET);
            outputThread.join();

            printReport();
            System.out.println();
            if (!stats.detectedSnis.isEmpty()) {
                System.out.println("[Detected Domains/SNIs]");
                stats.detectedSnis.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().displayName()));
            }
            System.out.println();
            System.out.println("Output written to: " + outputFile);
        }
    }

    private void printBanner() {
        int totalFastPaths = config.numLoadBalancers() * config.fpsPerLoadBalancer();
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║             DPI ENGINE v2.0 (Multi-threaded)                ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     ║%n",
            config.numLoadBalancers(),
            config.fpsPerLoadBalancer(),
            totalFastPaths);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }

    private void printReport() {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                      ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Total Packets:      %12d                           ║%n", stats.totalPackets.get());
        System.out.printf("║ Total Bytes:        %12d                           ║%n", stats.totalBytes.get());
        System.out.printf("║ TCP Packets:        %12d                           ║%n", stats.tcpPackets.get());
        System.out.printf("║ UDP Packets:        %12d                           ║%n", stats.udpPackets.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Forwarded:          %12d                           ║%n", stats.forwarded.get());
        System.out.printf("║ Dropped:            %12d                           ║%n", stats.dropped.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ THREAD STATISTICS                                           ║");
        for (LoadBalancerWorker loadBalancer : loadBalancers) {
            System.out.printf("║   LB%d dispatched:   %12d                           ║%n", loadBalancer.id, loadBalancer.dispatched.get());
        }
        for (FastPathWorker fastPath : fastPaths) {
            System.out.printf("║   FP%d processed:    %12d                           ║%n", fastPath.id, fastPath.processed.get());
        }
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                   APPLICATION BREAKDOWN                     ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        List<Map.Entry<AppType, AtomicLong>> sortedApps = new ArrayList<>(stats.appCounts.entrySet());
        sortedApps.sort(Comparator.comparingLong((Map.Entry<AppType, AtomicLong> entry) -> entry.getValue().get()).reversed());
        DecimalFormat percentFormat = new DecimalFormat("0.0");

        long totalPackets = stats.totalPackets.get();
        for (Map.Entry<AppType, AtomicLong> entry : sortedApps) {
            double pct = totalPackets == 0 ? 0.0 : (100.0 * entry.getValue().get() / totalPackets);
            int barLength = (int) (pct / 5);
            String bar = "#".repeat(Math.max(0, barLength));
            System.out.printf("║ %-15s%8d %5s%% %-20s  ║%n",
                entry.getKey().displayName(),
                entry.getValue().get(),
                percentFormat.format(pct),
                bar);
        }
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    private final class LoadBalancerWorker implements Runnable {
        private final int id;
        private final List<FastPathWorker> workers;
        private final BlockingQueue<PacketJob> queue = new LinkedBlockingQueue<>(10_000);
        private final AtomicLong dispatched = new AtomicLong();
        private final Thread thread;

        private LoadBalancerWorker(int id, List<FastPathWorker> workers) {
            this.id = id;
            this.workers = workers;
            this.thread = new Thread(this, "lb-" + id);
        }

        private void start() {
            thread.start();
        }

        private void join() throws InterruptedException {
            thread.join();
        }

        @Override
        public void run() {
            try {
                while (true) {
                    PacketJob job = queue.take();
                    if (job == POISON_PACKET) {
                        break;
                    }
                    FastPathWorker worker = workers.get(Math.floorMod(job.tuple().hashCode(), workers.size()));
                    worker.queue.put(job);
                    dispatched.incrementAndGet();
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private final class FastPathWorker implements Runnable {
        private final int id;
        private final BlockingQueue<PacketJob> queue = new LinkedBlockingQueue<>(10_000);
        private final Map<FiveTuple, FlowEntry> flows = new ConcurrentHashMap<>();
        private final AtomicLong processed = new AtomicLong();
        private final Thread thread;

        private FastPathWorker(int id) {
            this.id = id;
            this.thread = new Thread(this, "fp-" + id);
        }

        private void start() {
            thread.start();
        }

        private void join() throws InterruptedException {
            thread.join();
        }

        @Override
        public void run() {
            try {
                while (true) {
                    PacketJob job = queue.take();
                    if (job == POISON_PACKET) {
                        break;
                    }
                    processed.incrementAndGet();
                    FlowEntry flow = flows.computeIfAbsent(job.tuple(), FlowEntry::new);
                    flow.packets++;
                    flow.bytes += job.rawPacket().data().length;

                    if (!flow.classified) {
                        classify(job, flow);
                    }

                    if (!flow.blocked) {
                        flow.blocked = rules.isBlocked(job.tuple().srcIp(), flow.appType, flow.sni);
                    }

                    stats.appCounts.computeIfAbsent(flow.appType, ignored -> new AtomicLong()).incrementAndGet();
                    if (flow.sni != null && !flow.sni.isBlank()) {
                        stats.detectedSnis.put(flow.sni, flow.appType);
                    }

                    if (flow.blocked) {
                        stats.dropped.incrementAndGet();
                    } else {
                        stats.forwarded.incrementAndGet();
                        outputQueue.put(job);
                    }
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }

        private void classify(PacketJob job, FlowEntry flow) {
            byte[] data = job.rawPacket().data();
            if (job.tuple().dstPort() == 443 && job.payloadLength() > 5) {
                String sni = SniExtractor.extractTlsSni(data, job.payloadOffset(), job.payloadLength());
                if (sni != null) {
                    flow.sni = sni;
                    flow.appType = NetUtil.classifyFromSni(sni);
                    flow.classified = true;
                    return;
                }
            }

            if (job.tuple().dstPort() == 80 && job.payloadLength() > 10) {
                String host = SniExtractor.extractHttpHost(data, job.payloadOffset(), job.payloadLength());
                if (host != null) {
                    flow.sni = host;
                    flow.appType = NetUtil.classifyFromSni(host);
                    flow.classified = true;
                    return;
                }
            }

            if (job.tuple().dstPort() == 53 || job.tuple().srcPort() == 53) {
                flow.appType = AppType.DNS;
                flow.classified = true;
                return;
            }

            if (job.tuple().dstPort() == 443) {
                flow.appType = AppType.HTTPS;
            } else if (job.tuple().dstPort() == 80) {
                flow.appType = AppType.HTTP;
            }
        }
    }

    private record PacketJob(
        int id,
        FiveTuple tuple,
        RawPacket rawPacket,
        int payloadOffset,
        int payloadLength,
        int tcpFlags,
        int protocol
    ) {
    }

    private static final class FlowEntry {
        private final FiveTuple tuple;
        private AppType appType = AppType.UNKNOWN;
        private String sni;
        private long packets;
        private long bytes;
        private boolean blocked;
        private boolean classified;

        private FlowEntry(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }

    private static final class Stats {
        private final AtomicLong totalPackets = new AtomicLong();
        private final AtomicLong totalBytes = new AtomicLong();
        private final AtomicLong forwarded = new AtomicLong();
        private final AtomicLong dropped = new AtomicLong();
        private final AtomicLong tcpPackets = new AtomicLong();
        private final AtomicLong udpPackets = new AtomicLong();
        private final Map<AppType, AtomicLong> appCounts = new ConcurrentHashMap<>();
        private final Map<String, AppType> detectedSnis = new ConcurrentHashMap<>();
    }
}
