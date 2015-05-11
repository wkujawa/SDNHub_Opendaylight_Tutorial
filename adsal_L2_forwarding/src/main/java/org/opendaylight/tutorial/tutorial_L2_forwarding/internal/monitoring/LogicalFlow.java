package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import org.opendaylight.controller.sal.match.Match;

public class LogicalFlow {
    protected final int id;
    protected final Match match;
    protected final String srcIP;
    protected final String dstIP;
    //TODO add stats

    public LogicalFlow(Match match, String srcIP, String dstIP, int id) {
        this.id = id;
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.match = match;
    }

    public int getId() {
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
