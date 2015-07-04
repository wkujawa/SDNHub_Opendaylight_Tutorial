/*
 * Copyright (C) 2015 Wiktor Kujawa

 Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
 You may not use this file except in compliance with this License.
 You may obtain a copy of the License at

    http://www.gnu.org/licenses/gpl-3.0.txt

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 implied.

 *
 */
package org.opendaylight.controller.tee.internal.monitoring;

import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.tee.internal.monitoring.shortestpath.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class representing route between two hosts. Identified by ID.
 *
 * @author Wiktor Kujawa
 *
 */
public class Route implements Comparable<Route>{
    private static final Logger logger = LoggerFactory.getLogger(Route.class);

    private Path<Device, Link> path;
    private boolean isActive = false;
    private long packetsDropped = 0;
    private long availableBandwidth = 0;
    private long bandwidth = 0;
    private long cost = 0;
    private final int id;
    private Collection<LogicalFlow> flows = new ConcurrentLinkedDeque<LogicalFlow>();

    public Route(Path<Device, Link> p, int id) {
        this.id = id;
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

    public int getId() {
        return id;
    }

    public void addFlow(LogicalFlow flow) {
        flows.add(flow);
    }

    /**
     * Remove logical flow that wraps flow.
     * @param flow
     */
    public void removeFlow(Flow flow) {
        Iterator<LogicalFlow> iter = flows.iterator();
        while(iter.hasNext()) {
            LogicalFlow lFlow = iter.next();
            if (lFlow.equals(flow)) {
                logger.debug("Removed: {}", lFlow);
                iter.remove();
            }
        }
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
                    2*link.getBandwidth() - link.getUsage());
        }
        int bwpartSquare = (int) ((2*Utils.MB*100 - availableBandwidth) / Utils.MB);
        bwpartSquare *= bwpartSquare;
        cost = path.getHops() /*+ flows.size()*/ + bwpartSquare;
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
