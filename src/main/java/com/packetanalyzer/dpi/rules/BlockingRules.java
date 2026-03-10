package com.packetanalyzer.dpi.rules;

import com.packetanalyzer.dpi.model.AppType;
import com.packetanalyzer.dpi.util.NetUtil;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;

public final class BlockingRules {
    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final List<String> blockedDomains = new CopyOnWriteArrayList<>();

    public void blockIp(String ip) {
        blockedIps.add(NetUtil.parseIpv4ToInt(ip));
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    public void blockApp(String app) {
        AppType appType = AppType.fromDisplayName(app);
        if (appType == null) {
            System.err.println("[Rules] Unknown app: " + app);
            return;
        }
        blockedApps.add(appType);
        System.out.println("[Rules] Blocked app: " + appType.displayName());
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    public boolean isBlocked(int srcIp, AppType appType, String sni) {
        if (blockedIps.contains(srcIp)) {
            return true;
        }
        if (blockedApps.contains(appType)) {
            return true;
        }
        if (sni == null) {
            return false;
        }
        String lowerSni = sni.toLowerCase();
        for (String blockedDomain : blockedDomains) {
            if (lowerSni.contains(blockedDomain)) {
                return true;
            }
        }
        return false;
    }
}
