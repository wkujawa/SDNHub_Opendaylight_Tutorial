/*
 * Copyright (C) 2014 SDN Hub

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

package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.opendaylight.controller.hosttracker.IfIptoHost;
import org.opendaylight.controller.hosttracker.IfNewHostNotify;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.core.Property;
import org.opendaylight.controller.sal.core.UpdateType;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
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
import org.opendaylight.controller.sal.reader.FlowOnNode;
import org.opendaylight.controller.sal.topology.TopoEdgeUpdate;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.NetUtils;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.statisticsmanager.IStatisticsManager;
import org.opendaylight.controller.switchmanager.IInventoryListener;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.topologymanager.ITopologyManager;
import org.opendaylight.controller.topologymanager.ITopologyManagerAware;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.ArpTable;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Device;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Link;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.LogicalFlow;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.NetworkMonitor;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Route;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.RoutesMap;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Utils;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.InetAddresses;

public class TutorialL2Forwarding implements IListenDataPacket,
        ITopologyManagerAware, IfNewHostNotify, IInventoryListener,
        ITEE{
    private static final Logger logger = LoggerFactory
            .getLogger(TutorialL2Forwarding.class);
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

    void moveFlowEmergency(NodeConnector connector) {
        for(FlowOnNode flowOnNode : statisticsManager.getFlows(connector.getNode())) {
            Flow flow = flowOnNode.getFlow();
            for (Action action : flow.getActions()) {
                if (action.equals(new Output(connector))) {
                    logger.info("Moving flow {}", flow);
                    Match match = flow.getMatch();
                    MatchField srcField = match.getField(MatchType.DL_SRC);
                    MatchField dstField = match.getField(MatchType.DL_DST);
                    logger.info("Removing {} <-> {}", srcField.getValue(), dstField.getValue());
                    clearRoute((byte[])srcField.getValue(), (byte[])dstField.getValue());
                    //Remove all routes and find again K shortest paths (Will be done on Packet IN).
                    //Of course it is not optimal solution. //TODO
                    routesMap.removeRoutes((byte[])srcField.getValue(), (byte[])dstField.getValue());

                    // It will be programmed in standard way in reaction to PacketIn
                    continue;
                }
            }
        }
    }

    ////////////////////
    // IListenDataPacket
    ////////////////////
    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
        if (inPkt == null) {
            return PacketResult.IGNORED;
        }

        logger.debug("Got packet {}", inPkt.toString());

        Packet packet = this.dataPacketService.decodeDataPacket(inPkt);

        if (!(packet instanceof Ethernet)) {
            return PacketResult.IGNORED;
        } else {
            Object payload = packet.getPayload();
            byte[] srcMAC = ((Ethernet) packet).getSourceMACAddress();
            byte[] dstMAC = ((Ethernet) packet).getDestinationMACAddress();

           if (NetUtils.isBroadcastMACAddr(srcMAC) || NetUtils.isBroadcastMACAddr(dstMAC)) {
                //logger.info("Broadcast {} -> {}", Utils.mac2str(srcMAC), Utils.mac2str(dstMAC));
                //floodPacket(inPkt); //FIXME cannot do that with loops in network
                return PacketResult.IGNORED;
            }

            short ethType = ((Ethernet) packet).getEtherType();
            if (ethType == EtherTypes.IPv4.shortValue()) {
                logger.info("Got packet {} -> {} at {}", Utils.mac2str(srcMAC),
                        Utils.mac2str(dstMAC), inPkt.getIncomingNodeConnector()
                                .getNodeConnectorIDString());
                logger.info("Ethtype: "+((Ethernet) packet).getEtherType());

                if (!routesMap.getRoutes(srcMAC, dstMAC).isEmpty()) {
                    logger.error("Route should be already programmed. Loosing packet.");
                    //TODO Send it with Packet Out
                    return PacketResult.IGNORED;
                }

                if (payload instanceof IPv4) {
                    InetAddress srcIP = NetUtils.getInetAddress(((IPv4) payload).getSourceAddress());
                    InetAddress dstIP = NetUtils.getInetAddress(((IPv4) payload).getDestinationAddress());
                    logger.info("Discovering.."); //TODO is it better to first query for host ?
                    Future<HostNodeConnector> fsrc = hostTracker.discoverHost(srcIP);
                    Future<HostNodeConnector> fdst = hostTracker.discoverHost(dstIP);

                    try {
                        HostNodeConnector src = fsrc.get();
                        HostNodeConnector dst = fdst.get();

                        // Flow leading to host
                        // TODO do not duplicate
                        flowToHost(srcMAC, src.getnodeConnector());
                        flowToHost(dstMAC, dst.getnodeConnector());

                        logger.info("{} () at {}",
                                srcIP, Utils.mac2str(srcMAC), src.getnodeconnectorNode().getNodeIDString());
                        logger.info("{} () at {}",
                                dstIP, Utils.mac2str(dstMAC), dst.getnodeconnectorNode().getNodeIDString());
                        arpTable.put(BitBufferHelper.toNumber(srcMAC),srcIP.getHostAddress());
                        arpTable.put(BitBufferHelper.toNumber(dstMAC),dstIP.getHostAddress());

                        logger.info("Looking for k-paths");
                        List<Route> routes = Utils.PathsToRoutes(networkMonitor.getKShortestPath(src.getnodeconnectorNode(), dst.getnodeconnectorNode(),K));


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
                        Route bestRoute = routesMap.getBestRoute(srcMAC, dstMAC);

                        logger.info("--- K Shortest Paths ---"); //TODO remove debug logs
                        for (Route route : routes) {
                            logger.info("Path:");
                            for (Device device : route.getPath().getVertices()) {
                                logger.info("Device: "+device);
                            }
                            logger.info("Cost: {} PDR: {} Active: {}",route.getCost(),route.getPacketsDropped(), route.isActive());
                        }
                        logger.info("------------------------");

                        programFlow((Ethernet) packet, bestRoute);

                        // TODO first packet still is lost
                        // is it to late ?
                        // is it to fast ?
                        // wrong node connector ? send to all host node connectors
                        try {
                            Thread.sleep(2000);
                            RawPacket rawPacket = new RawPacket(inPkt);
                            rawPacket.setOutgoingNodeConnector(dst.getnodeConnector()); //TODO is it ok, shouldn't take that from route?
                            logger.info("Sending Packet: {}",
                                    rawPacket.getOutgoingNodeConnector());
                            dataPacketService.transmitDataPacket(rawPacket);
                        } catch (ConstructionException e) {
                            logger.error("Cannot construct packet: {}",e);
                        }

                        return PacketResult.CONSUME;
                    } catch (InterruptedException | ExecutionException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                } else {
                    logger.info("Not IPV4");
                }
            }

            return PacketResult.IGNORED;
        }
    }

    private boolean programFlow(Ethernet ethpacket, Route route) {
        // Graph is undirected so we need to figure out which connector is for source and which for destination
        Node lastNode = route.getPath().getSource().getNode();
        route.setActive(true); //TODO obsolete
        route.addFlow(new LogicalFlow(makeMatch(ethpacket, false)));
        route.addFlow(new LogicalFlow(makeMatch(ethpacket, true)));
        int i=0;
        for (Link link: route.getPath().getEdges()) {
            logger.info("Path "+i+" : "+link.getSourceConnector().getNode().getNodeIDString()+" - "
                        +link.getDestinationConnector().getNode().getNodeIDString()+" "+link.toString());

            if (lastNode.equals(link.getSourceConnector().getNode())) {
                flowS2S(ethpacket, link.getSourceConnector(), link.getDestinationConnector());
                lastNode = link.getDestinationConnector().getNode();
            } else {
                flowS2S(ethpacket, link.getDestinationConnector(), link.getSourceConnector());
                lastNode = link.getSourceConnector().getNode();
            }
        }
        return true; //TODO error handling
    }

    private boolean flowToHost(byte [] mac, NodeConnector connector) {
        Match match = new Match();
        match.setField(new MatchField(MatchType.DL_DST, mac.clone()));

        List<Action> actions = new ArrayList<Action>();
        actions.add(new Output(connector));

        Flow f = new Flow(match, actions);

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

    private boolean flowS2S(Ethernet ethpacket,
            NodeConnector incoming_connector, NodeConnector outgoing_connector) {
        return (programFlow(incoming_connector, ethpacket, false) &&
                programFlow(outgoing_connector, ethpacket, true));
    }

    private Match makeMatch(Ethernet ethpacket, boolean reversed) {
        Match match = new Match();
        byte[] srcMAC = !reversed ? ethpacket.getSourceMACAddress() : ethpacket.getDestinationMACAddress();
        byte[] dstMAC = !reversed ? ethpacket.getDestinationMACAddress() : ethpacket.getSourceMACAddress();

        match.setField(new MatchField(MatchType.DL_SRC, srcMAC.clone()));
        match.setField(new MatchField(MatchType.DL_DST, dstMAC.clone()));
        return match;
    }

    private boolean programFlow(NodeConnector connector, Match match) {
        List<Action> actions = new ArrayList<Action>();
        actions.add(new Output(connector));

        Flow f = new Flow(match, actions);
        logger.info("Programming flow {} on {}", f, connector.getNode()); //TODO change to debug

        Status status = programmer.addFlow(connector.getNode(), f);

        if (!status.isSuccess()) {
            logger.warn(
                    "SDN Plugin failed to program the flow: {}. The failure is: {}",
                    f, status.getDescription());
            return false;
        } else {
            return true;
        }
    }

    private boolean programFlow(NodeConnector connector, Ethernet ethpacket, boolean reversed) {
        Match match = makeMatch(ethpacket, reversed);
        List<Action> actions = new ArrayList<Action>();
        actions.add(new Output(connector));

        Flow f = new Flow(match, actions);

        Status status = programmer.addFlow(connector.getNode(), f);

        if (!status.isSuccess()) {
            logger.warn(
                    "SDN Plugin failed to program the flow: {}. The failure is: {}",
                    f, status.getDescription());
            return false;
        } else {
            return true;
        }
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
    public void notifyHTClient(HostNodeConnector arg0) {
        logger.info("notifyHTClient: {} connected to {}", arg0
                .getNetworkAddressAsString(), arg0.getnodeconnectorNode()
                .getNodeIDString());
        networkMonitor.addHost(arg0);
    }

    @Override
    public void notifyHTClientHostRemoved(HostNodeConnector arg0) {
        logger.info("notifyHTClientHostRemoved: {} removed from {}", arg0
                .getNetworkAddressAsString(), arg0.getnodeconnectorNode()
                .getNodeIDString());
        networkMonitor.removeHost(arg0);
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
    public Collection<Route> getRoutes(String srcIP, String dstIP) {
        Long srcMac = arpTable.getMac(srcIP);
        Long dstMac = arpTable.getMac(dstIP);
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

    // TODO TODO change to remove flows from just from nodes that wheren't in old route
    private void removeOlderFlow(LogicalFlow logicalFlow, Route route) {
        Match match = logicalFlow.getMatch();
        route.removeFlow(logicalFlow);
        List<Link> path = route.getPath().getEdges();
        for (Link link : path) {
            List<NodeConnector> connectors = new ArrayList<NodeConnector>();
            connectors.add(link.getSourceConnector());
            connectors.add(link.getDestinationConnector());
            for (NodeConnector connector : connectors) {
                FlowOnNode flowOnNodeToRemove = null;
                for(FlowOnNode flowOnNode : statisticsManager.getFlows(connector.getNode())) {
                    Flow flow = flowOnNode.getFlow();
                    if (match.equals(flow.getMatch())) {
                        // Find older matching flow
                        if (flowOnNodeToRemove == null) {
                            flowOnNodeToRemove = flowOnNode;
                        } else {
                            if (flowOnNode.getDurationSeconds() > flowOnNodeToRemove.getDurationSeconds()) {
                                flowOnNodeToRemove = flowOnNode;
                            }
                            Flow flowToRemove = flowOnNodeToRemove.getFlow();
                            logger.info("Removing flow {}", flowToRemove);
                            programmer.removeFlow(connector.getNode(), flowToRemove);
                        }
                    }
                }
                if (flowOnNodeToRemove == null) {
                    logger.error("Didn't find flow for match: {} on {}", match, connector.getNode());
                }
            }
        }
    }

    private HostNodeConnector getHostNodeConnectorByMac(byte [] mac) {
        String srcIP = arpTable.getIP(BitBufferHelper.toNumber(mac));
        return hostTracker.hostFind(InetAddresses.forString(srcIP));
    }

    private void programFlow(LogicalFlow logicalFlow, Route route) {
        Match match = logicalFlow.getMatch();
        route.addFlow(logicalFlow);
        byte[] srcMac = (byte[]) match.getField(MatchType.DL_SRC).getValue();
        byte[] dstMac = (byte[]) match.getField(MatchType.DL_DST).getValue();
        HostNodeConnector srcConnector = getHostNodeConnectorByMac(srcMac);
        HostNodeConnector dstConnector = getHostNodeConnectorByMac(dstMac);

        Node pathFirstNode = route.getPath().getSource().getNode();
        Node previousNode = null; // Helps keep links in good direction
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
            previousNode = dstConnector.getnodeconnectorNode();
        } else {
            reverse = false;
            listIterator = links.listIterator();
            previousNode = srcConnector.getnodeconnectorNode();
        }

        while(reverse ? listIterator.hasPrevious() : listIterator.hasNext()) {
            Link link = reverse ? listIterator.previous() : listIterator.next();
            logger.info("Link {} -> {}", link.getSourceConnector(), link.getDestinationConnector());
            if (previousNode.equals(link.getSourceConnector().getNode())) {
                programFlow(link.getDestinationConnector(), match);
                previousNode = link.getDestinationConnector().getNode();
            } else {
                programFlow(link.getSourceConnector(), match);
                previousNode = link.getSourceConnector().getNode();
            }
        }
    }

    @Override
    public boolean moveFlow(UUID fromRoute, UUID flow, UUID toRoute) {
        Route srcRoute = routesMap.getRouteByUUID(fromRoute);
        Route dstRoute = routesMap.getRouteByUUID(toRoute);

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
            if (logicalFlow.getId().equals(flow)) {
                flowToMove = logicalFlow;
                break;
            }
        }

        if (flowToMove != null) {
            logger.info("Moving flow "+flow);
            logger.info("1. Programming flow");
            programFlow(flowToMove, dstRoute);
            logger.info("2. Removing old flow");
            removeOlderFlow(flowToMove, srcRoute);
        } else {
            logger.error("Could't find flow "+flow);
            return false;
        }
        return true;
    }

}
