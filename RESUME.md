# Resume Content

## Short Resume Bullets

- Built a Java-based deep packet inspection engine that parses PCAP files, decodes Ethernet/IPv4/TCP/UDP traffic, and classifies flows using five-tuple tracking.
- Implemented TLS SNI and HTTP Host extraction in Java to identify application traffic and support rule-based filtering by IP, domain, and application type.
- Designed both single-threaded and multi-threaded packet-processing pipelines, including worker queues and flow-consistent hashing for concurrent DPI execution.
- Packaged the system as a Maven-based Java project with a runnable jar and CLI workflows for packet analysis, traffic filtering, and demo-ready local execution.

## Stronger Resume Version

- Engineered a Java deep packet inspection system for offline network traffic analysis, including PCAP binary parsing, protocol decoding, flow tracking, and filtered PCAP output generation.
- Developed traffic classification logic using TLS ClientHello SNI and HTTP Host extraction to map network flows to application categories such as YouTube, GitHub, Spotify, and TikTok.
- Built a concurrent DPI pipeline with load-balancer and fast-path worker stages using queue-based coordination and five-tuple hashing to preserve per-flow processing consistency.
- Delivered the project as a clean Java-only Maven codebase with runnable CLI modes for analysis, single-threaded filtering, and multi-threaded filtering, suitable for technical demos and portfolio review.

## One-Line Resume Summary

Java networking project that performs PCAP parsing, TLS/HTTP traffic classification, and multithreaded rule-based packet filtering.

## Skills You Can Associate With This Project

- Java
- Maven
- Networking
- Packet Parsing
- PCAP
- TCP/IP
- Multithreading
- Concurrent Queues
- CLI Applications
- Binary Data Processing
