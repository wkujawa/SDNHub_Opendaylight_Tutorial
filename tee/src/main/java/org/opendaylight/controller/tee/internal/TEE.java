/*
 * Copyright (C) 2014 SDN Hub
   Copyright (C) 2015 Wiktor Kujawa

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

package org.opendaylight.controller.tee.internal;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.opendaylight.controller.hosttracker.IfIptoHost;
import org.opendaylight.controller.hosttracker.IfNewHostNotify;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Drop;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.Host;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.core.Property;
import org.opendaylight.controller.sal.core.UpdateType;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerListener;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.packet.UDP;
import org.opendaylight.controller.sal.reader.FlowOnNode;
import org.opendaylight.controller.sal.topology.TopoEdgeUpdate;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.NetUtils;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.statisticsmanager.IStatisticsManager;
import org.opendaylight.controller.switchmanager.IInventoryListener;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.tee.internal.monitoring.ArpTable;
import org.opendaylight.controller.tee.internal.monitoring.Device;
import org.opendaylight.controller.tee.internal.monitoring.Link;
import org.opendaylight.controller.tee.internal.monitoring.LogicalFlow;
import org.opendaylight.controller.tee.internal.monitoring.NetworkMonitor;
import org.opendaylight.controller.tee.internal.monitoring.Route;
import org.opendaylight.controller.tee.internal.monitoring.RoutesMap;
import org.opendaylight.controller.tee.internal.monitoring.Utils;
import org.opendaylight.controller.tee.internal.monitoring.shortestpath.Path;
import org.opendaylight.controller.topologymanager.ITopologyManager;
import org.opendaylight.controller.topologymanager.ITopologyManagerAware;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.InetAddresses;

public class TEE implements IListenDataPacket,
        ITopologyManagerAware, IfNewHostNotify, IInventoryListener,
        IFlowProgrammerListener,ITEE{
    private static final Logger logger = LoggerFactory
            .getLogger(TEE.class);
    private ISwitchManager switchManager = null;
    private IFlowProgrammerService programmer = null;
    private IDataPacketService dataPacketService = null;
    private ITopologyManager topologyManager = null;
    private IStatisticsManager statisticsManager = null;
    private IfIptoHost hostTracker = null;
    private NetworkMonitor networkMonitor = null;

    private int K = 5;
    private RoutesMap routesMap = new RoutesMap();
    private ArpTable arpTable = new ArpTable();

    // Match configuration, read from configuration
    private boolean useTpDst = false;
    private boolean useTpSrc = false;
    private boolean useNwProto = false;
    // Flow timeouts, read from configuration
    private static short MOVING_TIMEOUT = 10; // idle timeout for flow to be removed
    private static short FLOW_TIMEOUT = 60;  // timeout for ordinary flow

    private static short FLOW_PRIORITY = 100;  // default priority
    private static short HOST_FLOW_PRIORITY = 200;  // host flow priority

    private static short MULTICAST_DROP_PRIORITY = 250;
    private static short MULTICAST_FLOW_PRIORITY = 300;
    private static short MULTICAST_PORT = 12345;

    // Last used id for Route
    private static int lastRouteId = 0;
    // Last used id for LogicalFLow
    private static int lastFlowId = 0;

    void setDataPacketService(IDataPacketService s) {
        this.dataPacketService = s;
    }

    void unsetDataPacketService(IDataPacketService s) {
        if (this.dataPacketService == s) {
            this.dataPacketService = null;
        }
    }

    void setFlowProgrammerService(IFlowProgrammerService s) {
        this.programmer = s;
    }

    void unsetFlowProgrammerService(IFlowProgrammerService s) {
        if (this.programmer == s) {
            this.programmer = null;
        }
    }

    void setSwitchManager(ISwitchManager s) {
        logger.debug("SwitchManager set");
        this.switchManager = s;
    }

    void unsetSwitchManager(ISwitchManager s) {
        if (this.switchManager == s) {
            logger.debug("SwitchManager removed!");
            this.switchManager = null;
        }
    }

    void setTopologyManager(ITopologyManager s) {
        logger.debug("ITopologyManager set");
        this.topologyManager = s;
    }

    void unsetTopologyManager(ITopologyManager s) {
        if (this.topologyManager == s) {
            logger.debug("ITopologyManager removed!");
            this.topologyManager = null;
        }
    }

    void setStatisticsManager(IStatisticsManager s) {
        logger.debug("IStatisticsManager set");
        this.statisticsManager = s;
    }

    void unsetStatisticsManager(IStatisticsManager s) {
        if (this.statisticsManager == s) {
            logger.debug("IStatisticsManager removed!");
            this.statisticsManager = null;
        }
    }

    void setHostTracker(IfIptoHost s) {
        logger.debug("IfIptoHost set");
        this.hostTracker = s;
    }

    void unsetHostTracker(IfIptoHost s) {
        if (this.hostTracker == s) {
            logger.debug("IfIptoHost removed!");
            this.hostTracker = null;
        }
    }

    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */
    void init() {
        logger.info("Initialized");
        // Disabling the SimpleForwarding and ARPHandler bundle to not conflict
        // with this one
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass())
                .getBundleContext();
        for (Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getSymbolicName().contains("simpleforwarding")) {
                try {
                    bundle.uninstall();
                } catch (BundleException e) {
                    logger.error(
                            "Exception in Bundle uninstall "
                                    + bundle.getSymbolicName(), e);
                }
            }
        }

        readConfiguration();

        logger.info("Starting Network Monitor..");
        networkMonitor = new NetworkMonitor();
    }

    /**
     * Function called by the dependency manager when at least one dependency
     * become unsatisfied or when the component is shutting down because for
     * example bundle is being stopped.
     *
     */
    void destroy() {
    }

    /**
     * Function called by dependency manager after "init ()" is called and after
     * the services provided by the class are registered in the service registry
     *
     */
    void start() {
        logger.info("Started");
        networkMonitor.setStatisticsManager(statisticsManager);
        networkMonitor.setSwitchManager(switchManager);
        for (Node node : switchManager.getNodes()) {
            networkMonitor.addDevice(node);
        }
        //TODO get notifications for added and removed switches
        networkMonitor.addEdges(topologyManager.getEdges());
        for (HostNodeConnector c : hostTracker.getAllHosts()) {
            networkMonitor.addHost(c);
        }

        networkMonitor.start();
    }

    /**
     * Function called by the dependency manager before the services exported by
     * the component are unregistered, this will be followed by a "destroy ()"
     * calls
     *
     */
    void stop() {
        networkMonitor.stop();
        logger.info("Stopped");
    }

    /**
     * Retrieves user configurations from config.ini and updates:
     * <ul>
     *  <li>k value for k-shortest path</li>
     * </ul>
     */
    private void readConfiguration() {
        String kStr = System.getProperty("tee.k", "5");
        String matchFieldsStr = System.getProperty("tee.matchFields");
        String movingTimeoutStr = System.getProperty("tee.movingTimeout");
        String flowTimeoutStr = System.getProperty("tee.flowTimeout");

        if (matchFieldsStr != null) {
            matchFieldsStr.toUpperCase();
            if (matchFieldsStr.contains("NW_PROTO")) {
                useNwProto = true;
            }
            if (matchFieldsStr.contains("TP_SRC")) {
                useTpSrc = true;
            }
            if (matchFieldsStr.contains("TP_DST")) {
                useTpDst = true;
            }
        }


        if (kStr != null) {
            try {
                K = Integer.parseInt(kStr);
            } catch (Exception e) {
            }
        }

        if (movingTimeoutStr != null) {
            try {
                MOVING_TIMEOUT = Short.parseShort(movingTimeoutStr);
            } catch (Exception e) {
            }
        }

        if (flowTimeoutStr != null) {
            try {
                FLOW_TIMEOUT = Short.parseShort(flowTimeoutStr);
            } catch (Exception e) {
            }
        }

        if (FLOW_TIMEOUT == MOVING_TIMEOUT && FLOW_TIMEOUT != 0) {
            throw new RuntimeException("Check config.ini. FlowTimeout and MovingTimeout cannot be tha same.");
        }

        if (FLOW_TIMEOUT == 0) {
            throw new RuntimeException("Check config.ini. FlowTimeout cannot be 0, because setting idle timeout later will not work. Why? ");
        }
    }

    ////////////////////
    // IListenDataPacket
    ////////////////////
    /**
     * When new packet arrives between host H1 and host H2 k-shortest path are found.
     * Same k-paths are added for H1->H2 and H2->H1.
     * Best route from k-path is chosen and programmed for both directions using match
     * created by @see makeMatch(). For each direction logical flow is created and assigned
     * to best route. Logical flow consist of unique id and match made by makeMatch that will
     * be enough to manage that flow in future.
     */
    @Override
    public synchronized PacketResult receiveDataPacket(RawPacket inPkt) {
        /* TODO
         * So far it is synchronized to avoid multiple programming of same packet.
         * It would be better to synchronized it individually for src,dst host pairs.
         * */

        if (inPkt == null) {
            return PacketResult.IGNORED;
        }

        Packet packet = this.dataPacketService.decodeDataPacket(inPkt);
        logger.trace("Got packet {}", packet.toString());

        if (!(packet instanceof Ethernet)) {
            logger.trace("Ignoring not ethernet packet");
            return PacketResult.IGNORED;
        } else {
            NodeConnector poConnector = null;  // Connector for Packet Out
            Object payload = packet.getPayload();
            byte[] srcMAC = ((Ethernet) packet).getSourceMACAddress();
            byte[] dstMAC = ((Ethernet) packet).getDestinationMACAddress();

           if (NetUtils.isBroadcastMACAddr(srcMAC) || NetUtils.isBroadcastMACAddr(dstMAC)) {
                //logger.info("Broadcast {} -> {}", Utils.mac2str(srcMAC), Utils.mac2str(dstMAC));
                //floodPacket(inPkt); //FIXME cannot do that with loops in network
                logger.trace("Ignoring broadcast packet {} -> {}", Utils.mac2str(srcMAC), Utils.mac2str(dstMAC));
                return PacketResult.IGNORED;
            }

            short ethType = ((Ethernet) packet).getEtherType();
            if (ethType == EtherTypes.IPv4.shortValue()) {
                logger.info("Got packet {} -> {} at {}", Utils.mac2str(srcMAC),
                        Utils.mac2str(dstMAC), inPkt.getIncomingNodeConnector()
                                .getNodeConnectorIDString());

                HostNodeConnector srcHostConnector = null;
                HostNodeConnector dstHostConnector = null;

                if (payload instanceof IPv4) {
                    InetAddress srcIP = NetUtils.getInetAddress(((IPv4) payload).getSourceAddress());
                    InetAddress dstIP = NetUtils.getInetAddress(((IPv4) payload).getDestinationAddress());

                    IPv4 ipv4Packet = (IPv4) payload;
                    //Multicast simulation - ignore UDP traffic on port 12345
                    if (ipv4Packet.getPayload() instanceof UDP) {
                        UDP udpPacket = (UDP) ipv4Packet.getPayload();
                        if (udpPacket.getDestinationPort() == MULTICAST_PORT) {
                            logger.info("Multicast packet (UDP::{}) - ignoring", MULTICAST_PORT);
                            //TODO could add temporary rule to drop all packet with destination 12345 to not overload controler if proper rules for multicast are not installed before
                            dropMulticast(inPkt.getIncomingNodeConnector());
                            return PacketResult.CONSUME;
                        }
                    }

                    // Host discovery, known (and programmed) hosts are cached in arpTable
                    srcHostConnector = arpTable.getNodeConnector(BitBufferHelper.getLong(srcMAC));
                    Future<HostNodeConnector> fsrc = null;
                    if (srcHostConnector == null) {
                        logger.info("Discovering {} ...", srcIP.toString());
                        fsrc = hostTracker.discoverHost(srcIP);
                    }

                    dstHostConnector = arpTable.getNodeConnector(BitBufferHelper.getLong(dstMAC));
                    Future<HostNodeConnector> fdst = null;
                    if (dstHostConnector == null) {
                        logger.info("Discovering {} ...", dstIP.toString());
                        fdst = hostTracker.discoverHost(dstIP);
                    }

                    if (srcHostConnector == null) {
                        try {
                            srcHostConnector = fsrc.get();
                            // Flow leading to host
                            flowToHost(srcMAC, srcHostConnector.getnodeConnector());
                            arpTable.put(BitBufferHelper.toNumber(srcMAC), srcIP.getHostAddress(), srcHostConnector);
                            logger.info("{} () at {}", srcIP, Utils.mac2str(srcMAC),
                                    srcHostConnector.getnodeconnectorNode().getNodeIDString());
                        } catch (InterruptedException | ExecutionException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                    }

                    if (dstHostConnector == null) {
                        try {
                            dstHostConnector = fdst.get();
                            // Flow leading to host
                            flowToHost(dstMAC, dstHostConnector.getnodeConnector());
                            arpTable.put(BitBufferHelper.toNumber(dstMAC), dstIP.getHostAddress(), dstHostConnector);
                            logger.info("{} () at {}", dstIP, Utils.mac2str(dstMAC),
                                    dstHostConnector.getnodeconnectorNode().getNodeIDString());
                        } catch (InterruptedException | ExecutionException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                    }
                } else {
                    logger.error("Not IPV4. Not programming.");
                    return PacketResult.KEEP_PROCESSING;
                }

                List<Route> routes = routesMap.getRoutes(srcMAC, dstMAC);
                if (routes.isEmpty()) {
                    //If both host are connected to same node don't need to find route
                    if (srcHostConnector.getnodeconnectorNode().equals(dstHostConnector.getnodeconnectorNode())) {
                        poConnector = dstHostConnector.getnodeConnector();
                    } else {
                        logger.info("Looking for k-paths");
                        routes = pathsToRoutes(networkMonitor.getKShortestPath(srcHostConnector.getnodeconnectorNode(), dstHostConnector.getnodeconnectorNode(),K));

                        logger.info("--- K Shortest Paths ---"); //TODO remove debug logs
                        for (Route route : routes) {
                            logger.info("Path:");
                            for (Device device : route.getPath().getVertices()) {
                                logger.info("Device: "+device);
                            }
                            logger.info("Cost: {} PDR: {}",route.getCost(),route.getPacketsDropped());
                        }
                        logger.info("------------------------");

                        routesMap.addRoutes(routes, srcMAC, dstMAC);
                        routesMap.addRoutes(routes, dstMAC, srcMAC);
                    }
                } else {
                    Match match = makeMatch((Ethernet) packet, false);
                    boolean found = false;
                    for (Route route : routes) {
                        for (LogicalFlow logicalFlow : route.getFlows()) {
                            if (logicalFlow.equals(match)) {
                                found = true;
                                break;
                            }
                        }
                        if (found) {
                            break;
                        }
                    }

                    // Route is programmed. Just send packet as Packet-Out.
                    if (found) {
                        Route bestRoute = routesMap.getBestRoute(srcMAC, dstMAC);
                        poConnector = getOutputConnector(bestRoute, srcHostConnector);
                    }
                }

                // Program routes in both way for the first time
                if (poConnector == null) { //Need to program route
                    Route bestRoute = routesMap.getBestRoute(srcMAC, dstMAC);
                    programRouteBidirect((Ethernet) packet, bestRoute);

                    poConnector = getOutputConnector(bestRoute, srcHostConnector);
                }

                try {
                    RawPacket rawPacket = new RawPacket(inPkt);
                    rawPacket.setOutgoingNodeConnector(poConnector);
                    logger.info("Sending Packet: {}",
                            rawPacket.getOutgoingNodeConnector());
                    dataPacketService.transmitDataPacket(rawPacket);
                } catch (ConstructionException e) {
                    logger.error("Cannot construct packet: {}",e);
                }

                logger.debug("Packet consumed");
                return PacketResult.CONSUME;
            }
            logger.trace("Packet ignored - not IPv4");
            return PacketResult.IGNORED;
        }
    }

    ////////////////////
    // Flows programming
    ////////////////////
    /**
     * Programs flows on route to handle given packet in both ways.
     * Creates logical flows for it.
     *
     * @param ethpacket - match will be made based on that
     * @param route - route to program
     * @return
     */
    private boolean programRouteBidirect(Ethernet ethpacket, Route route) {
        boolean ret1 = programRoute(makeLogicalFlow(ethpacket, false), route);
        boolean ret2 = programRoute(makeLogicalFlow(ethpacket, true), route);

        return ret1 && ret2;
    }

    private Match makeFlowToHostMatch(byte [] mac) {
        Match match = new Match();
        match.setField(new MatchField(MatchType.DL_DST, mac.clone()));
        return match;
    }

    private boolean flowToHost(byte [] mac, NodeConnector connector) {
        Match match = makeFlowToHostMatch(mac);

        List<Action> actions = new ArrayList<Action>();
        actions.add(new Output(connector));

        Flow f = new Flow(match, actions);
        f.setPriority(HOST_FLOW_PRIORITY);

        logger.info("Programming flow to {} : {}", mac, f);

        Node node = connector.getNode();
        Status status = programmer.addFlow(node, f);

        if (!status.isSuccess()) {
            logger.warn(
                    "SDN Plugin failed to program the flow: {}. The failure is: {}",
                    f, status.getDescription());
            return false;
        } else {
            return true;
        }
    }

    private boolean removeFlowToHost(HostNodeConnector connector) {
        byte [] mac = connector.getDataLayerAddressBytes();
        Match match = makeFlowToHostMatch(mac);
        Node node = connector.getnodeconnectorNode();
        for(FlowOnNode flowOnNode : statisticsManager.getFlows(node)) {
            Flow flow = flowOnNode.getFlow();
            if (match.equals(flow.getMatch()) && flow.getPriority() == HOST_FLOW_PRIORITY) {
                logger.info("Removing flow {}", flow);
                Status status = programmer.removeFlow(node, flow);

                if (!status.isSuccess()) {
                    logger.warn(
                            "SDN Plugin failed to modify the flow: {}. The failure is: {}",
                            flow, status.getDescription());
                    return false;
                } else {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean programRoute(LogicalFlow logicalFlow, Route route) {
        Match match = logicalFlow.getMatch();
        route.addFlow(logicalFlow);
        if (logicalFlow.isMulticast()) {
            return programMulticastRoute(match, route);
        } else {
            return programRoute(match, route);
        }
    }

    /**
     * Programs nodes on route to handle flows with given match.
     * Programming from destination node to source node in order to
     * seamlessly move flows and not "loose" packets.
     *
     * @param match - match for flows to be programmed
     * @param route - route to be programmed for given match
     * @return
     */
    private boolean programRoute(Match match, Route route) {
        byte[] srcMac = (byte[]) match.getField(MatchType.DL_SRC).getValue();
        byte[] dstMac = (byte[]) match.getField(MatchType.DL_DST).getValue();
        HostNodeConnector srcConnector = getHostNodeConnectorByMac(srcMac);
        HostNodeConnector dstConnector = getHostNodeConnectorByMac(dstMac);

        Node pathFirstNode = route.getPath().getSource().getNode();
        Node currentNode = null; // Node common between previous and current link
        NodeConnector secondNodeConnector = null;  // Connector of second node
        boolean reverse = false;
        ListIterator<Link> listIterator = null;
        List<Link> links = route.getPath().getEdges();

        logger.info("Programming path from {} to {}", Utils.mac2str(srcMac), Utils.mac2str(dstMac));
        logger.info("Route:");
        for (Link link: links) {
            logger.info("{} ->  {}", link.getSourceConnector(),
                    link.getDestinationConnector());
        }

        // Program in reverse order than flow so next switches know how to handle packets
        if (pathFirstNode.equals(srcConnector.getnodeconnectorNode())) {
            reverse = true;
            listIterator = links.listIterator(links.size());
        } else {
            reverse = false;
            listIterator = links.listIterator();
        }

        // Exploring path from the end
        currentNode = dstConnector.getnodeconnectorNode();
        boolean ret = true;
        while(reverse ? listIterator.hasPrevious() : listIterator.hasNext()) {
            Link link = reverse ? listIterator.previous() : listIterator.next();
            logger.info("Link {} -> {}", link.getSourceConnector(), link.getDestinationConnector());

            if (currentNode.equals(link.getSourceConnector().getNode())) {
                secondNodeConnector = link.getDestinationConnector();
            } else {
                secondNodeConnector = link.getSourceConnector();
            }

            ret &= programFlow(secondNodeConnector, match, FLOW_PRIORITY, FLOW_TIMEOUT);

            // Second node will be in next link
            currentNode = secondNodeConnector.getNode();
        }

        return ret;
    }

    private boolean programMulticastRoute(Match match, Route route) {
        Node currentNode = route.getPath().getSource().getNode();
        NodeConnector firstNodeConnector=null, secondNodeConnector = null;

        List<Link> links = route.getPath().getEdges();
        ListIterator<Link> listIterator = links.listIterator();

        logger.info("Route:");
        for (Link link: links) {
            logger.info("{} ->  {}", link.getSourceConnector(),
                    link.getDestinationConnector());
        }

        boolean ret = true;
        while(listIterator.hasNext()) {
            Link link = listIterator.next();
            logger.info("Link {} -> {}", link.getSourceConnector(), link.getDestinationConnector());

            if (currentNode.equals(link.getSourceConnector().getNode())) {
                firstNodeConnector = link.getSourceConnector();
                secondNodeConnector = link.getDestinationConnector();
            } else {
                firstNodeConnector = link.getDestinationConnector();
                secondNodeConnector = link.getSourceConnector();
            }

            Set<Action> actionsSet = new HashSet<>();
            actionsSet.addAll(getMulticastActions(firstNodeConnector.getNode()));
            List<Action> actions = new ArrayList<Action>();
            actions.addAll(actionsSet);
            actions.add(new Output(firstNodeConnector));

            ret &= programFlow(firstNodeConnector.getNode(), match, actions, MULTICAST_FLOW_PRIORITY, (short) 0);

            // Second node will be in next link
            currentNode = secondNodeConnector.getNode();
        }
        return ret;
    }

    private boolean removeFlowFromRoute(LogicalFlow logicalFlow, Route route) {
        Path<Device, Link> path = route.getPath();
        for (Device device : path.getVertices()) {
            Node node = device.getNode();
            for(FlowOnNode flowOnNode : statisticsManager.getFlows(node)) {
                Flow flow = flowOnNode.getFlow();
                if (logicalFlow.equals(flow)) {
                    logger.info("Removing flow {}", flow);
                    Status status = programmer.removeFlow(node, flow);
                    if (!status.isSuccess()) {
                        logger.warn(
                                "SDN Plugin failed to modify the flow: {}. The failure is: {}",
                                flow, status.getDescription());
                        return false;
                    } else {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private Match makeMatch(Ethernet ethpacket, boolean reversed){
        Match match = new Match();
        byte[] srcMAC = !reversed ? ethpacket.getSourceMACAddress() : ethpacket.getDestinationMACAddress();
        byte[] dstMAC = !reversed ? ethpacket.getDestinationMACAddress() : ethpacket.getSourceMACAddress();
        Packet payload = ethpacket.getPayload();
        if (payload instanceof IPv4) {
            IPv4 ipPacket = (IPv4) payload;
            if (useNwProto) {
                match.setField(new MatchField(MatchType.DL_TYPE, ethpacket.getEtherType())); // Needed to match on NW_PROTO
                match.setField(new MatchField(MatchType.NW_PROTO, ipPacket.getProtocol()));
            }
            Short tpSrc = null;
            Short tpDst = null;
            Packet tlPacket = payload.getPayload();
            if (tlPacket instanceof TCP) {
                tpSrc = ((TCP) tlPacket).getSourcePort();
                tpDst = ((TCP)tlPacket).getDestinationPort();
            } else if (tlPacket instanceof UDP) {
                tpSrc = ((UDP) tlPacket).getSourcePort();
                tpDst = ((UDP)tlPacket).getDestinationPort();
            }

            if (reversed) {
                Short tmp = tpSrc;
                tpSrc = tpDst;
                tpDst = tmp;
            }

            if (useTpSrc && tpSrc != null) {
                match.setField(new MatchField(MatchType.TP_SRC, tpSrc));
            }
            if (useTpDst && tpDst != null) {
                match.setField(new MatchField(MatchType.TP_DST, tpDst));
            }
        } else {
            logger.error("Not IPv4 packet. Not making match.");
            return null;
        }

        match.setField(new MatchField(MatchType.DL_SRC, srcMAC.clone()));
        match.setField(new MatchField(MatchType.DL_DST, dstMAC.clone()));
        return match;
    }

    private LogicalFlow makeLogicalFlow(Ethernet ethpacket, boolean reversed){
        Match match = makeMatch(ethpacket, reversed);
        if (match == null) {
            return null;
        }

        Packet payload = ethpacket.getPayload();
        IPv4 ipPacket = (IPv4) payload;
        String srcIP = !reversed ? NetUtils.getInetAddress(ipPacket.getSourceAddress()).getHostAddress()
                : NetUtils.getInetAddress(ipPacket.getDestinationAddress()).getHostAddress();
        String dstIP = !reversed ? NetUtils.getInetAddress(ipPacket.getDestinationAddress()).getHostAddress()
                : NetUtils.getInetAddress(ipPacket.getSourceAddress()).getHostAddress();;

        LogicalFlow newFlow = new LogicalFlow(match, srcIP, dstIP, lastFlowId++, FLOW_PRIORITY);
        logger.debug("Added: {}", newFlow);
        return newFlow;
    }

    private LogicalFlow makeMulticastLogicalFlow(String switchId, String otherId){
        Match match = makeMulticastMatch();
        if (match == null) {
            return null;
        }

        LogicalFlow newFlow = new LogicalFlow(match, switchId, otherId, lastFlowId++, MULTICAST_FLOW_PRIORITY);
        logger.debug("Added: {}", newFlow);
        return newFlow;
    }

    private boolean programFlow(NodeConnector connector, Match match, short priority, short timeout) {
        List<Action> actions = new ArrayList<Action>();
        actions.add(new Output(connector));
        return programFlow(connector.getNode(), match, actions, priority, timeout);
    }

    private boolean programFlow(Node node, Match match, List<Action> actions, short priority, short timeout) {
        Flow f = new Flow(match, actions);
        f.setIdleTimeout(timeout);
        f.setPriority(priority);
        logger.info("Programming flow {} on {}", f, node); //TODO change to debug

        Status status = programmer.addFlow(node, f);

        if (!status.isSuccess()) {
            logger.warn(
                    "SDN Plugin failed to program the flow: {}. The failure is: {}",
                    f, status.getDescription());
            return false;
        } else {
            return true;
        }
    }

    private Match makeMulticastMatch() {
        Match match = new Match();
        match.setField(new MatchField(MatchType.DL_TYPE, (short) 0x0800)); // Needed to match on NW_PROTO
        match.setField(new MatchField(MatchType.NW_PROTO, (byte) 17));
        match.setField(new MatchField(MatchType.TP_DST, MULTICAST_PORT));
        return match;
    }

    private void dropMulticast(NodeConnector connector) {
        Match match = makeMulticastMatch();
        List<Action> actions = new ArrayList<Action>();
        actions.add(new Drop());
        Flow flow = new Flow(match, actions);
        flow.setPriority(MULTICAST_DROP_PRIORITY);
        logger.info("Programming multicast drop flow {} on {}", flow, connector.getNode());

        Status status = programmer.addFlow(connector.getNode(), flow);

        if (!status.isSuccess()) {
            logger.warn(
                    "SDN Plugin failed to program the flow: {}. The failure is: {}",
                    flow, status.getDescription());
        }
    }

    /**
     * Gets action from old route on given node.
     * @param node
     * @param route
     * @return
     */
    private Action getOldMulticastAction(Node node, Route route) {
        Node currentNode = node;
        NodeConnector firstNodeConnector=null, secondNodeConnector = null;

        List<Link> links = route.getPath().getEdges();
        ListIterator<Link> listIterator = links.listIterator();

        while(listIterator.hasNext()) {
            Link link = listIterator.next();
            logger.info("Link {} -> {}", link.getSourceConnector(), link.getDestinationConnector());

            if (currentNode.equals(link.getSourceConnector().getNode())) {
                firstNodeConnector = link.getSourceConnector();
                secondNodeConnector = link.getDestinationConnector();
            } else {
                firstNodeConnector = link.getDestinationConnector();
                secondNodeConnector = link.getSourceConnector();
            }

            if (firstNodeConnector.getNode().equals(node)) {
                return new Output(firstNodeConnector);
            }

            // Second node will be in next link
            currentNode = secondNodeConnector.getNode();
        }
        return null;
    }

    private boolean moveMulticastFlow(LogicalFlow flow, Route srcRoute, Route dstRoute){
        Node currentNode = dstRoute.getPath().getTarget().getNode();
        NodeConnector firstNodeConnector=null;

        List<Link> links = dstRoute.getPath().getEdges();
        ListIterator<Link> listIterator = links.listIterator(links.size());

        logger.info("Route:");
        for (Link link: links) {
            logger.info("{} ->  {}", link.getSourceConnector(),
                    link.getDestinationConnector());
        }

        // Reconfigure flows in reversed order. If switch was in old route remove that action.
        boolean ret = true;
        while(listIterator.hasPrevious()) {
            Link link = listIterator.previous();
            logger.info("Link {} -> {}", link.getSourceConnector(), link.getDestinationConnector());

            if (currentNode.equals(link.getSourceConnector().getNode())) {
                firstNodeConnector = link.getDestinationConnector();
            } else {
                firstNodeConnector = link.getSourceConnector();
            }

            Set<Action> actionsSet = new HashSet<>();
            actionsSet.addAll(getMulticastActions(firstNodeConnector.getNode()));
            Action toRemoveAction = getOldMulticastAction(firstNodeConnector.getNode(), srcRoute);
            if (toRemoveAction != null) {
                if (!actionsSet.remove(toRemoveAction)) {
                    logger.warn("Could not find {} on {} that should be removed from action set.", toRemoveAction, firstNodeConnector.getNode());
                }
            }
            actionsSet.add(new Output(firstNodeConnector));
            List<Action> actions = new ArrayList<Action>();
            actions.addAll(actionsSet);

            ret &= programFlow(firstNodeConnector.getNode(), flow.getMatch(), actions, MULTICAST_FLOW_PRIORITY, (short) 0);

            // Second node will be in next link
            currentNode = firstNodeConnector.getNode();
        }

        //Remove flows from switches that are not in new route
        for (Device device : srcRoute.getPath().getVertices()) {
            if (dstRoute.getPath().getVertices().contains(device)) {
                continue;
            }
            Node node = device.getNode();
            Action action = getOldMulticastAction(node, srcRoute);
            if (action != null) {
                List<Action> actions = getMulticastActions(node);
                actions.remove(action);
                if (!actions.isEmpty()) {
                    ret &= programFlow(node, flow.getMatch(), actions, MULTICAST_FLOW_PRIORITY, (short) 0);
                } else { // There is no action so we should delete this flow
                    ret &= removeMulticastFlow(node);
                }
            } else {
                if (!node.equals(srcRoute.getPath().getTarget().getNode())) {
                    logger.error("There should not be action only for target node.");
                }
            }
        }

        // Update flow in routes
        dstRoute.addFlow(flow);
        srcRoute.removeFlow(flow);

        return ret;
    }

    private boolean removeMulticastFlow(Node node) {
        List<FlowOnNode> flowsOnNode = statisticsManager.getFlows(node);
        Match match = makeMulticastMatch();
        for (FlowOnNode flowOnNode : flowsOnNode) {
            Flow flow = flowOnNode.getFlow();
            if (flow.getMatch().equals(match) && flow.getPriority() == MULTICAST_FLOW_PRIORITY) {
                Status status = programmer.removeFlow(node, flow);
                if (status.isSuccess()) {
                    return true;
                } else {
                    logger.error("Unable to remove {} from {} : {}", flow,  node, status.getDescription());
                    return false;
                }
            }
        }
        return false;
    }

    private void clearRoute(byte[] srtMAC, byte[] dstMAC) {
        clearRouteOneWay(srtMAC, dstMAC);
        clearRouteOneWay(dstMAC, srtMAC);
    }

    private void clearRouteOneWay(byte[] srcMAC, byte[] dstMAC) {
        List<Route> routes = routesMap.getRoutes(srcMAC, dstMAC);
        for (Route route : routes) {
            List<Link> path = route.getPath().getEdges();
            for (Link link : path) {
                List<NodeConnector> connectors = new ArrayList<NodeConnector>();
                connectors.add(link.getSourceConnector());
                connectors.add(link.getDestinationConnector());
                for (NodeConnector connector : connectors) {
                    for(FlowOnNode flowOnNode : statisticsManager.getFlows(connector.getNode())) {
                        Flow flow = flowOnNode.getFlow();
                        for (Action action : flow.getActions()) {
                            if (action.equals(new Output(connector))) {
                                logger.info("Matching output {}", flow);
                                Match match = flow.getMatch();
                                MatchField srcField = match.getField(MatchType.DL_SRC);
                                MatchField dstField = match.getField(MatchType.DL_DST);
                                if (srcField.equals(new MatchField(MatchType.DL_SRC, srcMAC.clone()))
                                        && dstField.equals(new MatchField(MatchType.DL_DST, dstMAC.clone()))) {
                                    logger.info("Matching src and dst {}", flow);
                                    programmer.removeFlow(connector.getNode(), flow);
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    /**
     * Remove flows from logicalFlow that could be left after moving it from oldRoute to newRoute.
     * When new flow is programmed on node, flow with same Match will be updated.
     * So old flows are only on nodes from oldRoute that are not in newRoute.
     *
     * Flow are removed with delay to ensure that all packets have left old route.
     * This is done by setting short idle time to flow instead of just removing that flow.
     *
     * Removal is done in reversed order.
     *
     * Problem: Removing by idle timeout doesn't work if initially flow was permanent. Why ?
     * Value is set for flow properly but when counter exceeds idle timeout nothing happens.
     *
     * @param logicalFlow - flow to remove
     * @param oldRoute  - old route - logical flow was moved from it
     * @param newRoute - new route - logical flow was moved to it
     * @return
     */
    private boolean removeOlderFlow(LogicalFlow logicalFlow, Route oldRoute, Route newRoute) {
        Match match = logicalFlow.getMatch();
        oldRoute.removeFlow(logicalFlow);
        List<Device> oldDevices = oldRoute.getPath().getVertices();
        List<Device> newDevices = newRoute.getPath().getVertices();

        // Handle multicast flow different as they are simpler
        if (logicalFlow.isMulticast()) {
            // TMP not removing old flows, need to rethink and fix (actions can be cummulated, which ones to remove)
            //return removeOlderMulticastFlow(match, oldDevices, newDevices);
            return true;
        }

        byte[] srcMac = (byte[]) match.getField(MatchType.DL_SRC).getValue();
        HostNodeConnector srcConnector = getHostNodeConnectorByMac(srcMac);

        boolean reverse = false;
        ListIterator<Device> listIterator = null;
        if (oldRoute.getPath().getSource().getNode().equals(srcConnector.getnodeconnectorNode())) {
            reverse = true;
            listIterator = oldDevices.listIterator(oldDevices.size());
        } else {
            reverse = false;
            listIterator = oldDevices.listIterator();
        }

        boolean ret = true;
        while(reverse ? listIterator.hasPrevious() : listIterator.hasNext()) {
            Device device = reverse ? listIterator.previous() : listIterator.next();
            if (!newDevices.contains(device)) {
                Flow flowShort = null;
                for(FlowOnNode flowOnNode : statisticsManager.getFlows(device.getNode())) {
                    Flow flow = flowOnNode.getFlow();
                    if (match.equals(flow.getMatch())) {
                        flowShort = flow.clone();
                        flowShort.setIdleTimeout(MOVING_TIMEOUT);
                        logger.info("Setting idle timeout {} by flow add for {}", MOVING_TIMEOUT, flowShort);
                        Status status = programmer.addFlow(device.getNode(), flowShort);

                        if (!status.isSuccess()) {
                            logger.warn(
                                    "SDN Plugin failed to modify the flow: {}. The failure is: {}",
                                    flowShort, status.getDescription());
                            ret = false;
                        }
                    }
                }
                if (flowShort == null) {
                    logger.error("Didn't find flow for match: {} on {}", match, device.getNode());
                    ret = false;
                }
            }
        }
        return ret;
    }

    private List<Action> getMulticastActions(Node node) {
        Match multicastMatch = makeMulticastMatch();
        List<FlowOnNode> flowsOnNode = statisticsManager.getFlows(node);
        for (FlowOnNode flowOnNode : flowsOnNode) {
            Flow flow = flowOnNode.getFlow();
            if (flow.getMatch().equals(multicastMatch) && flow.getPriority() == MULTICAST_FLOW_PRIORITY) {
                logger.info("Found existing multicast flow with actions: {}", flow.getActions());
                return flow.getActions();
            }
         }

        return new LinkedList<>();
    }

    //TODO update
    private void moveFlowEmergency(NodeConnector connector) {
        for(FlowOnNode flowOnNode : statisticsManager.getFlows(connector.getNode())) {
            Flow flow = flowOnNode.getFlow();
            for (Action action : flow.getActions()) {
                if (action.equals(new Output(connector))) {
                    logger.info("Moving flow {}", flow);
                    Match match = flow.getMatch();
                    MatchField srcField = match.getField(MatchType.DL_SRC);
                    MatchField dstField = match.getField(MatchType.DL_DST);
                    logger.info("Removing {} <-> {}", Utils.mac2str((byte[])srcField.getValue()), Utils.mac2str((byte[])dstField.getValue()));
                    clearRoute((byte[])srcField.getValue(), (byte[])dstField.getValue());
                    //Remove all routes and find again K shortest paths (Will be done on Packet IN).
                    //Of course it is not optimal solution. //TODO
                    routesMap.removeRoutes((byte[])srcField.getValue(), (byte[])dstField.getValue());
                    routesMap.removeRoutes((byte[])dstField.getValue(), (byte[])srcField.getValue());
                    // It will be programmed in standard way in reaction to PacketIn
                    continue;
                }
            }
        }
    }

    ////////////////////////
    // Utilities
    ////////////////////////
    private NodeConnector getOutputConnector(Route bestRoute, HostNodeConnector srcHostConnector) {
        ArrayList<Link> links = bestRoute.getPath().getEdges();
        Link link = null;
        if (bestRoute.getPath().getTarget().getNode().equals(srcHostConnector.getnodeconnectorNode())) {
            // Dst node is on last link
            link = links.get(links.size()-1);
        } else {
            link = links.get(0);
        }

        if (link.getSourceConnector().getNode().equals(srcHostConnector.getnodeconnectorNode())) {
            return link.getSourceConnector();
        } else if (link.getDestinationConnector().getNode().equals(srcHostConnector.getnodeconnectorNode())) {
            return link.getDestinationConnector();
        } else {
            logger.error("Node connector for PacketOut not found. BUG");
            return null;
        }
    }

    private HostNodeConnector getHostNodeConnectorByMac(byte [] mac) {
        String srcIP = getIP(mac);
        return hostTracker.hostFind(InetAddresses.forString(srcIP));
    }

    private String getIP(byte [] mac) {
        return arpTable.getIP(BitBufferHelper.toNumber(mac));
    }

    private List<Route> pathsToRoutes(List<Path<Device, Link>> paths) {
        List<Route> routes = new LinkedList<Route>();
        for (Path<Device, Link> path : paths) {
            routes.add(new Route(path, lastRouteId++));
        }
        return routes;
    }

    /**
     * Sanity check - internal data (RoutesMap and ArpTable) should be empty.
     * @return true if passed, false if not passed
     */
    private boolean emptinessSanityCheck() {
        logger.info("Emptiness sanity check..");
        if (!routesMap.isEmpty()) {
            logger.error("FAILED. RoutesMap is not empty, but last host have been removed.");
            //TODO print routes map
            return false;
        }
        if (!arpTable.isEmpty()) {
            logger.error("FAILED. ArpTable is not empty, but last host have been removed.");
            arpTable.debugPrint();
            return false;
        }
        logger.info("PASSED");
        return true;
    }

    ////////////////////////
    // ITopologyManagerAware
    ////////////////////////
    @Override
    public void edgeOverUtilized(Edge arg0) {
        logger.info("edgeOverUtilized");
    }

    @Override
    public void edgeUpdate(List<TopoEdgeUpdate> arg0) {
        logger.info("edgeUpdate");
        logger.info("Update:" + arg0.toString());
        networkMonitor.edgeUpdate(arg0);

        for (TopoEdgeUpdate edgeUpdate : arg0) {
            UpdateType type = edgeUpdate.getUpdateType();
            Edge edge = edgeUpdate.getEdge();

            switch (type) {
            case ADDED:
                break;
            case CHANGED:
                break;
            case REMOVED:
                // Flows are symmetric on both nodes so we need to check
                // what paths are on one node
                moveFlowEmergency(edge.getHeadNodeConnector());
                break;
            default:
                break;
            }
        }
    }

    @Override
    public void edgeUtilBackToNormal(Edge arg0) {
        logger.info("edgeUtilBackToNormal");
    }

    //////////////////
    // IfNewHostNotify
    //////////////////
    @Override
    public void notifyHTClient(HostNodeConnector hostNodeConnector) {
        logger.info("notifyHTClient: {} connected to {}", hostNodeConnector
                .getNetworkAddressAsString(), hostNodeConnector.getnodeconnectorNode()
                .getNodeIDString());
        networkMonitor.addHost(hostNodeConnector);

        //If needed update ArpTable and program specila flow to host
        Long mac = BitBufferHelper.getLong(hostNodeConnector.getDataLayerAddressBytes());
        String ip = hostNodeConnector.getNetworkAddressAsString();
        HostNodeConnector entry = arpTable.getNodeConnector(mac);
        if (entry != null && !entry.equals(hostNodeConnector)) {
            logger.info("Information about {} changed. Old: {} new: {}", ip, entry, hostNodeConnector);
            notifyHTClientHostRemoved(entry);
        }
        logger.info("Caching new info about {} at {}", ip, hostNodeConnector.getnodeconnectorNode()
                .getNodeIDString());
        arpTable.put(mac, ip, hostNodeConnector);
        flowToHost(hostNodeConnector.getDataLayerAddressBytes(), hostNodeConnector.getnodeConnector());
    }

    @Override
    public void notifyHTClientHostRemoved(HostNodeConnector hostNodeConnecotr) {
        logger.info("notifyHTClientHostRemoved: {} removed from {}", hostNodeConnecotr
                .getNetworkAddressAsString(), hostNodeConnecotr.getnodeconnectorNode()
                .getNodeIDString());
        byte [] mac = hostNodeConnecotr.getDataLayerAddressBytes();
        removeFlowToHost(hostNodeConnecotr);
        networkMonitor.removeHost(hostNodeConnecotr);
        List<Route> routes = routesMap.getRoutes(mac);
        for (Route route : routes) {
            for (LogicalFlow logicalFlow : route.getFlows()) {
                //Remove logical flow from network
                removeFlowFromRoute(logicalFlow, route);
            }
        }
        routesMap.removeRoutes(mac);
        arpTable.remove(BitBufferHelper.getLong(mac));
        // Sanity check
        if (hostTracker.getAllHosts().isEmpty()) {
            //There is no hosts so ARP table and routes map should be empty
            emptinessSanityCheck();
        }
    }

    /////////////////////
    // IInventoryListener
    /////////////////////
    @Override
    public void notifyNode(Node arg0, UpdateType arg1,
            Map<String, Property> arg2) {
        logger.info("notifyNode id: {} type {}", arg0.getNodeIDString(), arg1);
        switch (arg1) {
        case ADDED:
            networkMonitor.addDevice(arg0);
            break;
        case CHANGED:
            //TODO
            logger.warn("notifyNode type CHANGED not yet implemented");
            break;
        case REMOVED:
            networkMonitor.removeDevice(arg0);
            //TODO remove Routes containing that node and move logical flows
            // Sanity check
            if (switchManager.getNodes().isEmpty()) {
                //There is no hosts so ARP table and routes map should be empty
                emptinessSanityCheck();
            }
            break;
        default:
            break;

        }
    }

    @Override
    public void notifyNodeConnector(NodeConnector arg0, UpdateType arg1,
            Map<String, Property> arg2) {
        logger.info("notifyNodeConnector");
    }

    ////////
    // ITEE
    ////////
    @Override
    public NetworkMonitor getNetworkMonitor() {
        return networkMonitor;
    }

    @Override
    public Set<HostNodeConnector> getAllHosts() {
        return hostTracker.getAllHosts();
    }

    @Override
    public Collection<Link> getLinks() {
        return networkMonitor.getLinks();
    }

    @Override
    public Collection<Device> getDevices() {
        return networkMonitor.getDevices();
    }

    @Override
    public Collection<LogicalFlow> getFlows() {
        Set<LogicalFlow> flows = new HashSet<LogicalFlow>();
        for (Route route : routesMap.getAllRoutes()) {
            flows.addAll(route.getFlows());
        }
        return flows;
    }

    @Override
    public Collection<Route> getRoutes(String srcIP, String dstIP) {
        Long srcMac = null, dstMac = null;
        if (srcIP.contains(".")) { // Getting routes by IP
            srcMac = arpTable.getMac(srcIP);
            dstMac = arpTable.getMac(dstIP);
        } else { // Getting routes between switches by switches id
            srcMac = Long.parseLong(srcIP);
            dstMac = Long.parseLong(dstIP);
        }
        Collection<Route> routes = null;

        if (srcMac != null && dstMac != null) {
            routes = routesMap.getRoutes(srcMac, dstMac);
        }

        if (routes == null) {
            return new LinkedList<Route>();
        } else {
            return routes;
        }
    }

    @Override
    public boolean moveFlow(int fromRoute, int flow, int toRoute) {
        Route srcRoute = routesMap.getRouteById(fromRoute);
        Route dstRoute = routesMap.getRouteById(toRoute);

        if (fromRoute == toRoute) {
            logger.error("Not moving flow if src and dst route are the same.");
            return false;
        }

        if (srcRoute == null) {
            logger.error("Uknown route "+fromRoute);
            return false;
        }

        if (dstRoute == null) {
            logger.error("Uknown route "+toRoute);
            return false;
        }

        LogicalFlow flowToMove = null;
        for (LogicalFlow logicalFlow : srcRoute.getFlows()) {
            if (logicalFlow.getId() == flow) {
                flowToMove = logicalFlow;
                break;
            }
        }

        if (flowToMove != null) {
            if (flowToMove.isMulticast()) {
                logger.info("Moving multicast flow "+flow);
                return moveMulticastFlow(flowToMove, srcRoute, dstRoute);
            } else {
            logger.info("Moving flow "+flow);
            logger.info("1. Programming flow");
            boolean ret =programRoute(flowToMove, dstRoute);
            logger.info("2. Removing old flow");
            ret &= removeOlderFlow(flowToMove, srcRoute, dstRoute);
            return ret;
            }
        } else {
            logger.error("Could't find flow "+flow);
            return false;
        }
    }

    private String unifyId(String id) {
        if (id.contains(":")) {
            id = id.replace(":", "");
            return String.valueOf(Long.parseLong(id, 16));
        }
        return id;
    }

    private Collection<String> unifyIds(Collection<String> ids) {
        Collection<String> unifiedIds = new LinkedList<>();
        for (String id : ids) {
            unifiedIds.add(unifyId(id));
        }
        return unifiedIds;
    }


    @Override
    public boolean configureMulticast(String switchId, Collection<String> clientsIds) {
        switchId = unifyId(switchId);
        clientsIds = unifyIds(clientsIds);
        logger.info("Multicast from switch {} to {}", switchId, clientsIds);

        Match match = makeMulticastMatch();
        Set<Action> actionsSet = new  HashSet<Action>();
        Node mainSwitch;
        Set<Node> nodes = switchManager.getNodes();
        for (Node node : nodes) {
            logger.info("Trying {}", node.getID());
            if (node.getID().toString().equals(switchId)) {
                logger.info("Found switch with id {}", switchId);
                mainSwitch = node;
                logger.info("Connectors {}", switchManager.getNodeConnectors(mainSwitch));
                Device mainDevice = networkMonitor.getDevice(mainSwitch);
                for (NodeConnector connector : switchManager.getNodeConnectors(mainSwitch)) {
                    Link link = mainDevice.getLink(connector.getNodeConnectorIDString());
                    if (link != null) {
                        if (!link.isHostLink()) {
                            NodeConnector secondConnector;
                            if (link.getSourceConnector().equals(connector)) {
                                secondConnector = link.getDestinationConnector();
                            } else {
                                secondConnector = link.getSourceConnector();
                            }
                            logger.info("Found second connector {} to {}", secondConnector.getNodeConnectorIDString(), secondConnector.getNode());
                            if (clientsIds.contains(secondConnector.getNode().getID().toString())) {
                                logger.info("Connector leads to one of the targets. Adding action");
                                actionsSet.add(new Output(connector));
                            }
                        } else {
                            List<Host> hosts = topologyManager.getHostsAttachedToNodeConnector(connector);
                            if (hosts != null) {
                                for (Host host : hosts) {
                                    if (clientsIds.contains(host.getNetworkAddressAsString())) {
                                        logger.info("Connector leads to host {}. Adding action", host.getNetworkAddressAsString());
                                        actionsSet.add(new Output(connector));
                                    }
                                }
                            }
                        }
                    }
                }
                actionsSet.addAll(getMulticastActions(mainSwitch));
                List<Action> actions = new ArrayList<Action>();
                actions.addAll(actionsSet);
                Flow flow = new Flow(match, actions);
                flow.setPriority(MULTICAST_FLOW_PRIORITY);
                logger.info("Programming multicast flow {} on {}", flow, mainSwitch);

                Status status = programmer.addFlow(mainSwitch, flow);

                if (!status.isSuccess()) {
                    logger.warn(
                            "SDN Plugin failed to program the flow: {}. The failure is: {}",
                            flow, status.getDescription());
                }
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean removeMulticast(String switchId,
            Collection<String> clientsIds) {
        switchId = unifyId(switchId);
        clientsIds = unifyIds(clientsIds);
        logger.info("Multicast on switch {} remove {}", switchId, clientsIds);

        Match match = makeMulticastMatch();
        Set<Action> actionsSet = new HashSet<>();
        Node mainSwitch;
        Set<Node> nodes = switchManager.getNodes();
        for (Node node : nodes) {
            if (node.getID().toString().equals(switchId)) {
                logger.info("Found switch with id {}", switchId);
                mainSwitch = node;
                actionsSet.addAll(getMulticastActions(mainSwitch));

                logger.info("Connectors {}", switchManager.getNodeConnectors(mainSwitch));
                Device mainDevice = networkMonitor.getDevice(mainSwitch);
                for (NodeConnector connector : switchManager.getNodeConnectors(mainSwitch)) {
                    Link link = mainDevice.getLink(connector.getNodeConnectorIDString());
                    if (link != null) {
                        if (!link.isHostLink()) {
                            NodeConnector secondConnector;
                            if (link.getSourceConnector().equals(connector)) {
                                secondConnector = link.getDestinationConnector();
                            } else {
                                secondConnector = link.getSourceConnector();
                            }
                            logger.info("Found second connector {} to {}", secondConnector.getNodeConnectorIDString(), secondConnector.getNode());
                            if (clientsIds.contains(secondConnector.getNode().getID().toString())) {
                                logger.info("Connector leads to one of the targets. Adding action");
                                actionsSet.remove(new Output(connector));
                            }
                        } else {
                            List<Host> hosts = topologyManager.getHostsAttachedToNodeConnector(connector);
                            if (hosts != null) {
                                for (Host host : hosts) {
                                    if (clientsIds.contains(host.getNetworkAddressAsString())) {
                                        logger.info("Connector leads to host {}. Adding action", host.getNetworkAddressAsString());
                                        actionsSet.remove(new Output(connector));
                                    }
                                }
                            }
                        }
                    }
                }
                List<Action> actions = new ArrayList<Action>();
                actions.addAll(actionsSet);
                Flow flow = new Flow(match, actions);
                if (actions.isEmpty()) {
                    return removeMulticastFlow(mainSwitch);
                }
                flow.setPriority(MULTICAST_FLOW_PRIORITY);

                logger.info("Programming multicast flow {} on {}", flow, mainSwitch);

                Status status = programmer.addFlow(mainSwitch, flow);

                if (!status.isSuccess()) {
                    logger.warn(
                            "SDN Plugin failed to program the flow: {}. The failure is: {}",
                            flow, status.getDescription());
                }
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean configureMulticastKPath(String switchId, String otherId) {
        switchId = unifyId(switchId);
        otherId = unifyId(otherId);
        Node firstSwitch = null, secondSwitch = null;
        Set<Node> nodes = switchManager.getNodes();
        logger.info("Getting nodes for switches {} and {}", switchId, otherId);
        for (Node node : nodes) {
            if (node.getID().toString().equals(switchId)) {
                firstSwitch = node;
            }
            if (node.getID().toString().equals(otherId)) {
                secondSwitch = node;
            }
        }
        if (firstSwitch == null || secondSwitch == null) {
            logger.error("Not found switches by ids: {}={} {}={}", switchId, firstSwitch, otherId, secondSwitch);
            return false;
        }
        firstSwitch.getID();
        List<Route> routes;
        logger.info("Looking for k-paths");
        routes = pathsToRoutes(networkMonitor.getKShortestPath(firstSwitch, secondSwitch, K));

        logger.info("--- K Shortest Paths ---");
        for (Route route : routes) {
            logger.info("Path:");
            for (Device device : route.getPath().getVertices()) {
                logger.info("Device: "+device);
            }
            logger.info("Cost: {} PDR: {}",route.getCost(),route.getPacketsDropped());
        }
        logger.info("------------------------");

        //TODO IDs might have conflict, maybe add some constant 0x5e000000
        logger.info("Adding routes for {} {}", (long) firstSwitch.getID(), (long) secondSwitch.getID());
        routesMap.addRoutes(routes, (long) firstSwitch.getID(), (long) secondSwitch.getID());
        // Multicast route is directed      // routesMap.addRoutes(routes, (long) secondSwitch.getID(), (long) secondSwitch.getID());
        Route bestRoute = routesMap.getBestRoute(routes);
        logger.info("Best route id: {}", bestRoute.getId());
        return programRoute(makeMulticastLogicalFlow(switchId, otherId), bestRoute);
    }

    //////////////////////////
    // IFlowProgrammerListener
    //////////////////////////
    @Override
    public void flowRemoved(Node node, Flow flow) {
        logger.info("Flow removed {} from {}",flow, node);
        // Recognizing old flows that was moved to other route by timeout
        // Cannot do it with priority because that either will create new flow
        // or with flow mod cause flow removed message for original flow
        if (flow.getIdleTimeout() == MOVING_TIMEOUT) {
            return;
        }
        routesMap.removeFlow(flow);
    }

    @Override
    public void flowErrorReported(Node node, long rid, Object err) {
        logger.info("flowErrorReported({}, {}, {})", node, rid, err);
    }

}
