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
import java.util.HashMap;
import java.util.Map;

import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.reader.FlowOnNode;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class Device {
    private Node mNode;
    private String mId;
    private DeviceType mType;
    private Map<String, Port> mPorts;
    private Map<Flow, FlowStatistics> mFlows;

    public Device(Node node) {
        mNode = node;
        mId = node.getNodeIDString();
        mType = DeviceType.SWITCH;
        mPorts = new HashMap<String, Port>();
        mFlows = new HashMap<Flow, FlowStatistics>();
    }

    public Device(String hostid) {
        mNode = null;
        mId = hostid;
        mType = DeviceType.HOST;
        mPorts = new HashMap<String, Port>();
        mFlows = new HashMap<Flow, FlowStatistics>();
    }

    public String getId() {
        return mId;
    }

    public DeviceType getType() {
        return mType;
    }

    /**
     * Returns port for given id.
     *
     * @param portId
     *            - port ID
     * @return port handle, null if don't exist.
     */
    public Port getPort(String portId) {
        return mPorts.get(portId);
    }

    /**
     * Returns link for given device's connector.
     * @param connectorId - NodeConnectorIDString for this device
     * @return Link between this and device
     */
    public Link getLink(String connectorId) {
        Link link = null;
        Port port = mPorts.get(connectorId);
        if (port!=null) {
            link = port.getLink();
        }
        return link;
    }

    public Node getNode() {
        return mNode;
    }

    /**
     * Returns flow statistics for given flow or "null" if not found.
     *
     * @param flow
     * @return flow statistics or null
     */
    public FlowStatistics getFlowStatistics(FlowOnNode flowOnNode) {
        FlowStatistics flowStatistics = mFlows.get(flowOnNode.getFlow());
        if (flowStatistics == null) {
            flowStatistics = new FlowStatistics(flowOnNode.getFlow(),
                    flowOnNode.getByteCount());
            mFlows.put(flowOnNode.getFlow(), flowStatistics);
        }
        return flowStatistics;
    }

    @JsonIgnore
    public Collection<FlowStatistics> getFlowStatistics() {
        return mFlows.values();
    }

    /**
     * Creates port if does not exist.
     *
     * @param portId
     *            - port ID
     * @return port - handle
     */
    public Port createPort(String portId) {
        if (mPorts.containsKey(portId)) {
            return mPorts.get(portId);
        } else {
            Port port = new Port(this, portId);
            mPorts.put(portId, port);
            return port;
        }
    }

    public void updateLinksStatistics(long time) {
        for (Port port : mPorts.values()) {
            Link link = port.getLink();
            if (link != null) {
                if (time > link.getUpdateTime()) {
                    // First device makes update
                    link.updateStatistic(time, port.getDataRate(), port.getDropCount());
                } else if (time == link.getUpdateTime()) {
                    if (!link.isHostLink()) {
                        // Do that only for links between switches. Host got
                        // stats only from one side.
                        // Second side of link makes update
                        // Statistic of link as average of both
                        long usage = (link.getUsage() + port.getDataRate()) / 2;
                        long drop = (link.getDropCount() + port.getDropCount()); //Sum of both ports
                        link.updateStatistic(time, usage, drop);
                    } else {
                        long usage = link.getUsage() + port.getDataRate();
                        link.updateStatistic(time, usage, port.getDropCount());
                    }
                }
            }
        }
    }

    // DEBUG
    public String debugInfo() {
        StringBuilder builder = new StringBuilder();
        builder.append("Device [" + mId + " type: " + mType + "\n");
        for (Port port : mPorts.values()) {
            builder.append(port.toString() + "\n");
        }
        return builder.toString();
    }

    @Override
    public String toString() {
        return mType + ":" + mId;
    }
}
