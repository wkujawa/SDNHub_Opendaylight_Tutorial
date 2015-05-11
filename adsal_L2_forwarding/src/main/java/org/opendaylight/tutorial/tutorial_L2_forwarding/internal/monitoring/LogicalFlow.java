package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.UUID;

import org.opendaylight.controller.sal.match.Match;

public class LogicalFlow {
    protected final UUID id;
    protected final Match match;
    protected final String srcIP;
    protected final String dstIP;
    //TODO add stats

    public LogicalFlow(Match match, String srcIP, String dstIP) {
        id = UUID.randomUUID();
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.match = match;
    }

    public UUID getId() {
        return id;
    }

    public Match getMatch() {
        return match;
    }

    public String getSrcIP() {
        return srcIP;
    }

    public String getDstIP() {
        return dstIP;
    }

}
