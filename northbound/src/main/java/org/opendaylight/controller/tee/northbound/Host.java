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
package org.opendaylight.controller.tee.northbound;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.tee.internal.monitoring.Utils;

/**
 * @author Wiktor Kujawa
 *
 */
public class Host {
    private String ip;
    private String mac;
    private String nodeId;
    private String portId;

    public Host(String ip, String mac, String nodeId, String portId) {
        this.ip=ip;
        this.mac=mac;
        this.nodeId=nodeId;
        this.portId=portId;
    }

    public Host(HostNodeConnector hostConnector) {
        this.ip = hostConnector.getNetworkAddressAsString();
        this.mac= Utils.mac2str(hostConnector.getDataLayerAddressBytes());
        this.nodeId = hostConnector.getnodeconnectorNode().getNodeIDString();
        this.portId = hostConnector.getnodeConnector().getNodeConnectorIDString();
    }

    public String getIp() {
        return ip;
    }

    public String getMac() {
        return mac;
    }

    public String getNodeId() {
        return nodeId;
    }

    public String getPortId() {
        return portId;
    }

}
