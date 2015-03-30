package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.Collection;
import java.util.LinkedList;
import java.util.UUID;

import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.shortestpath.Path;

/**
 * Class representing route between two hosts. Identified by UUID.
 *
 * @author Wiktor Kujawa
 *
 */
public class Route implements Comparable<Route>{
    private Path<Device, Link> path;
    private boolean isActive = false;
    private long packetsDropped = 0;
    private long availableBandwidth = 0;
    private long bandwidth = 0;
    private long cost = 0;
    private final UUID id;
    private Collection<LogicalFlow> flows = new LinkedList<LogicalFlow>();

    public Route(Path<Device, Link> p) {
        id = UUID.randomUUID();
        path = p;
        setBandwitdh();
    }

    public Path<Device, Link> getPath() {
        return path;
    }

    public void setPath(Path<Device, Link> path) {
        this.path = path;
        setBandwitdh();
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }

    public long getPacketsDropped() {
        return packetsDropped;
    }

    public void setPacketsDropped(long packetsDropped) {
        this.packetsDropped = packetsDropped;
    }

    public long getCost() {
        return cost;
    }

    public void setCost(long cost) {
        this.cost = cost;
    }

    public long getAvailableBandwidth() {
        return availableBandwidth;
    }

    private void setBandwitdh() {
        for (Link link : path.getEdges()) {
            bandwidth = Math.min(bandwidth,
                    link.getBandwidth());
        }
    }

    public long getBandwidth() {
        return bandwidth;
    }

    public long getHops() {
        return path.getHops();
    }

    public UUID getId() {
        return id;
    }

    public void addFlow(LogicalFlow flow) {
        flows.add(flow);
    }

    public void removeFlow(LogicalFlow flow) {
        flows.remove(flow);
    }

    public Collection<LogicalFlow> getFlows() {
        return flows;
    }

    /**
     * Calculates and sets cost of path.
     */
    public void evaluate() {
        availableBandwidth = Long.MAX_VALUE;
        for (Link link : path.getEdges()) {
            availableBandwidth = Math.min(availableBandwidth,
                    link.getBandwidth() - link.getUsage());
        }
        cost = path.getHops() + Utils.MB*100 - availableBandwidth;
    }

    @Override
    public int compareTo(Route o) {
        return (int)(cost - o.getCost());
    }

    @Override
    public String toString() {
        return "Route [path=" + path + ", isActive=" + isActive
                + ", packetsDropped=" + packetsDropped + ", cost=" + cost + ", availableBandwidth="+availableBandwidth+"]";
    }

}
