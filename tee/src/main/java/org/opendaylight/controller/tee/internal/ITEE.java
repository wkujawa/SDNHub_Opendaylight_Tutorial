/**
 * Interface of Traffic Engineering Engine
 */
package org.opendaylight.controller.tee.internal;

import java.util.Collection;
import java.util.Set;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.tee.internal.monitoring.Device;
import org.opendaylight.controller.tee.internal.monitoring.Link;
import org.opendaylight.controller.tee.internal.monitoring.LogicalFlow;
import org.opendaylight.controller.tee.internal.monitoring.NetworkMonitor;
import org.opendaylight.controller.tee.internal.monitoring.Route;

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
