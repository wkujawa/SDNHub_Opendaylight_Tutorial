package org.opendaylight.controller.tee.northbound;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Utils;

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
