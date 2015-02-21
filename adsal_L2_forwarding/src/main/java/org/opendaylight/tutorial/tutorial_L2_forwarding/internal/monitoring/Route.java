package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.shortestpath.Path;

public class Route implements Comparable<Route>{
    private Path<Device, Link> path;
    private boolean isActive = false;
    private long packetsDropped = 0;
    private long cost = 0;
    
    public Route(Path<Device, Link> p) {
        path = p;
    }

    public Path<Device, Link> getPath() {
        return path;
    }

    public void setPath(Path<Device, Link> path) {
        this.path = path;
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
    
    /**
     * Calculates and sets cost of path.
     */
    public void evaluate() {
        cost = path.getHops();
    }

    @Override
    public int compareTo(Route o) {
        return (int)(cost - o.getCost());
    }

    @Override
    public String toString() {
        return "Route [path=" + path + ", isActive=" + isActive
                + ", packetsDropped=" + packetsDropped + ", cost=" + cost + "]";
    }

}
