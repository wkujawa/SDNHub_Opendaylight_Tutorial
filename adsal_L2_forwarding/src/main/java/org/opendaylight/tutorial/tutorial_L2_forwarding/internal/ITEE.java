/**
 * Interface of Traffic Engineering Engine
 */
package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.util.Collection;
import java.util.Set;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Device;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Link;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.LogicalFlow;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.NetworkMonitor;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Route;

/**
 * @author Wiktor Kujawa
 *
 */
public interface ITEE {
    public NetworkMonitor getNetworkMonitor();

    public Set<HostNodeConnector> getAllHosts();

    public Collection<Link> getLinks();

    public Collection<Device> getDevices();

    public Collection<LogicalFlow> getFlows();

    public Collection<Route> getRoutes(String srcIP, String dstIP);

    public boolean moveFlow(int fromRoute, int flow, int toRoute); //TODO error handling
}
