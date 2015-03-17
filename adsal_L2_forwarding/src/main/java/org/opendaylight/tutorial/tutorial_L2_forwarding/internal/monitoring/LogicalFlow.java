package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.UUID;

import org.opendaylight.controller.sal.match.Match;

public class LogicalFlow {
    protected final UUID id;
    protected Match match;
    //TODO add stats

    public LogicalFlow(Match match) {
        id = UUID.randomUUID();
        this.match = match;
    }

    public UUID getId() {
        return id;
    }

    public Match getMatch() {
        return match;
    }
}
