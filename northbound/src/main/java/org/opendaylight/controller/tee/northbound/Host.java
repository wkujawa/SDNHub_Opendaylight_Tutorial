/**
 * 
 */
package org.opendaylight.controller.tee.northbound;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;

/**
 * @author v1t3x
 *
 */
public class Host {
    private String ip;
    private String nodeId;
    private String portId;

    public Host(String ip, String nodeId, String portId) {
        this.ip=ip;
        this.nodeId=nodeId;
        this.portId=portId;
    }
    
    public Host(HostNodeConnector hostConnector) {
        this.ip = hostConnector.getNetworkAddressAsString();
        this.nodeId = hostConnector.getnodeconnectorNode().getNodeIDString();
        this.portId = hostConnector.getnodeConnector().getNodeConnectorIDString();
    }

    public String getIp() {
        return ip;
    }

    public String getNodeId() {
        return nodeId;
    }

    public String getPortId() {
        return portId;
    }

}
