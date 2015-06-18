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
