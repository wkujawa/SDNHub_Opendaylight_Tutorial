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
import java.util.List;
import java.util.Map;
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
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Device;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Link;
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

public class TutorialL2Forwarding implements IListenDataPacket,
        ITopologyManagerAware, IfNewHostNotify, IInventoryListener {
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
                        
                        logger.info("{} at {}, {} at {}",
                                srcIP, src.getnodeconnectorNode().getNodeIDString(),
                                dstIP, dst.getnodeconnectorNode().getNodeIDString());
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
                        bestRoute.setActive(true);
                        
                        logger.info("--- K Shortest Paths ---"); //TODO remove debug logs
                        for (Route route : routes) {
                            logger.info("Path:");
                            for (Device device : route.getPath().getVertices()) {
                                logger.info("Device: "+device);
                            }
                            logger.info("Cost: {} PDR: {} Active: {}",route.getCost(),route.getPacketsDropped(), route.isActive());
                        }
                        logger.info("------------------------");
                        
                        List<Link> path = bestRoute.getPath().getEdges();
                        int i = 0;
                        
                        // Graph is undirected so we need to figure out which connector is for source and which for destination
                        Node lastNode = src.getnodeconnectorNode();
                        
                        for (Link link: path) {
                            logger.info("Path "+i+" : "+link.getSourceConnector().getNode().getNodeIDString()+" - "
                                        +link.getDestinationConnector().getNode().getNodeIDString()+" "+link.toString());
                            
                            if (lastNode.equals(link.getSourceConnector().getNode())) {
                                flowS2S((Ethernet)packet, link.getSourceConnector(), link.getDestinationConnector());
                                lastNode = link.getDestinationConnector().getNode();
                            } else {
                                flowS2S((Ethernet)packet, link.getDestinationConnector(), link.getSourceConnector());
                                lastNode = link.getSourceConnector().getNode();
                            }
                        }

                        // TODO first packet still is lost
                        // is it to late ?
                        // is it to fast ?
                        // wrong node connector ? send to all host node connectors
                        try {
                            Thread.sleep(2000);
                            RawPacket rawPacket = new RawPacket(inPkt);
                            rawPacket.setOutgoingNodeConnector(dst.getnodeConnector());
                            logger.info("Sending Packet: {} {}",rawPacket.getPacketData(), rawPacket.getOutgoingNodeConnector());
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
        byte[] srcMAC = ethpacket.getSourceMACAddress();
        byte[] dstMAC = ethpacket.getDestinationMACAddress();
        
        return (programFlow(incoming_connector, srcMAC, dstMAC) &&
                programFlow(outgoing_connector, dstMAC, srcMAC));
    }
    
    private boolean programFlow(NodeConnector connector, byte[] srcMAC, byte[] dstMAC) {
        Match match = new Match();
        match.setField(new MatchField(MatchType.DL_SRC, srcMAC.clone()));
        match.setField(new MatchField(MatchType.DL_DST, dstMAC.clone()));

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
        List<Link> path = routesMap.getActiveRoute(srcMAC, dstMAC).getPath().getEdges();
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
}
