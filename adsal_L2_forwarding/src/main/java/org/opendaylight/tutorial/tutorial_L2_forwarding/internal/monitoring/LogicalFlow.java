package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.match.Match;

public class LogicalFlow {
    protected final int id;
    protected final Match match;
    protected final short priority;
    protected final String srcIP;
    protected final String dstIP;
    //TODO add stats

    public LogicalFlow(Match match, String srcIP, String dstIP, int id, short priority) {
        this.id = id;
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.match = match;
        this.priority = priority;
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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + id;
        result = prime * result + ((match == null) ? 0 : match.hashCode());
        return result;
    }

    public boolean equals(Flow flow) {
        if (flow == null) {
            return false;
        }
        if (match.equals(flow.getMatch()))
            return false;
        if (priority != flow.getPriority())
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "LogicalFlow [id=" + id + ", match=" + match + ", priority="
                + priority + ", srcIP=" + srcIP + ", dstIP=" + dstIP + "]";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        LogicalFlow other = (LogicalFlow) obj;
        if (id != other.id)
            return false;
        if (match == null) {
            if (other.match != null)
                return false;
        } else if (!match.equals(other.match))
            return false;
        return true;
    }

}
