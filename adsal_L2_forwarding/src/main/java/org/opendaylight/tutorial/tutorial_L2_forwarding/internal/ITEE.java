/**
 * Interface of Traffic Engineering Engine
 */
package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.util.Collection;
import java.util.Set;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Device;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Link;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.NetworkMonitor;

/**
 * @author Wiktor Kujawa
 *
 */
public interface ITEE {
    public NetworkMonitor getNetworkMonitor();
    
    public Set<HostNodeConnector> getAllHosts();
    
    public Collection<Link> getLinks();
    
    public Collection<Device> getDevices();
}
