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
package org.opendaylight.controller.tee.internal.monitoring;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.GraphicsEnvironment;
import java.awt.Paint;
import java.awt.Stroke;
import java.text.DecimalFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.apache.commons.collections15.Transformer;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.Property;
import org.opendaylight.controller.sal.core.UpdateType;
import org.opendaylight.controller.sal.reader.FlowOnNode;
import org.opendaylight.controller.sal.reader.NodeConnectorStatistics;
import org.opendaylight.controller.sal.topology.TopoEdgeUpdate;
import org.opendaylight.controller.statisticsmanager.IStatisticsManager;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.tee.internal.monitoring.shortestpath.DijkstraKShortestPath;
import org.opendaylight.controller.tee.internal.monitoring.shortestpath.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.uci.ics.jung.algorithms.layout.FRLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.algorithms.shortestpath.DijkstraShortestPath;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.UndirectedSparseMultigraph;
import edu.uci.ics.jung.graph.util.EdgeType;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.DefaultModalGraphMouse;
import edu.uci.ics.jung.visualization.control.ModalGraphMouse.Mode;
import edu.uci.ics.jung.visualization.renderers.Renderer;

public class NetworkMonitor {
    private static final Logger logger = LoggerFactory
            .getLogger(NetworkMonitor.class);

    private int mUpdateInteval = 1000;
    private MonitorThread mWorker;
    private IStatisticsManager mStatisticsManager = null;
    private ISwitchManager mSwitchManager = null;

    /* Visualization works only when java.awt.headless = false*/
    private JFrame mFrame = null;
    private Graph<Device, Link> mGraph = null;
    private Layout<Device, Link> mVisualizer = null;
    private VisualizationViewer<Device, Link> mVisualizationViewer = null;

    DijkstraShortestPath<Device, Link> dijkstra = null;
    DijkstraKShortestPath<Device, Link> kDijkstra = null;
    Transformer<Link, ? extends Number> mTransformer = new LinkTransformer();

    private long mCurrentTime;

    /**
     * Collection of detected devices.
     */
    private final HashMap<String, Device> mDevices;

    private class MonitorThread extends Thread {
        @Override
        public void run() {
            super.run();
            logger.info("Monitor thread started.");
            while (!isInterrupted()) {
                mCurrentTime = System.currentTimeMillis(); //TODO maybe it can be taken from statistics

                processStatistics();

                repaint();

                try {
                    Thread.sleep(mUpdateInteval);
                } catch (InterruptedException e) {
                    // Closing thread
                    logger.info("Monitor will be stopped.");
                    Thread.currentThread().interrupt();
                }
            }
            logger.info("Monitor thread stopped.");
        }
    }

    public NetworkMonitor() {
        mDevices = new HashMap<String, Device>();
        mGraph = new UndirectedSparseMultigraph<Device, Link>();
        dijkstra = new DijkstraShortestPath<Device, Link>(mGraph, mTransformer);
        kDijkstra = new DijkstraKShortestPath<Device, Link>(mGraph);

        if (!GraphicsEnvironment.isHeadless()) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    initGraphView();
                }
            });
        }
        readConfiguration();
        init();
    }

    private void init() {
        mWorker = new MonitorThread();
    }

    public void start() {
        mWorker.start();
    }

    public void stop() {
        mWorker.interrupt();
        if (!GraphicsEnvironment.isHeadless()) {
            mFrame.setVisible(false);
            mFrame.dispose();
        }
    }

    private void readConfiguration() {
        String updateIntervalStr = System.getProperty("tee.nm.updateInterval", "5");

        if (updateIntervalStr != null) {
            try {
                mUpdateInteval = Integer.parseInt(updateIntervalStr) * 1000;
            } catch (Exception e) {
            }
        }

    }


    private void initGraphView() {
        // The Layout<V, E> is parameterized by the vertex and edge types
        mVisualizer = new FRLayout<Device, Link>(mGraph);
        mVisualizer.initialize();
        mVisualizer.setSize(new Dimension(650, 650)); // sets the initial size
                                                      // of the space
        mVisualizationViewer = new VisualizationViewer<Device, Link>(
                mVisualizer);
        mVisualizationViewer.setPreferredSize(new Dimension(650, 650));

        DefaultModalGraphMouse<Device, Link> graphMouse = new DefaultModalGraphMouse<Device, Link>();
        graphMouse.setMode(Mode.PICKING);
        mVisualizationViewer.setGraphMouse(graphMouse);

        mVisualizationViewer.getRenderer().getVertexLabelRenderer()
                .setPosition(Renderer.VertexLabel.Position.CNTR);
        mVisualizationViewer.getRenderContext().setVertexLabelTransformer(
                new Transformer<Device, String>() {
                    @Override
                    public String transform(Device device) {
                        StringBuilder builder = new StringBuilder();
                        builder.append("<html><center><br><br><br><br>"+(device.getType()==DeviceType.HOST?"<br>":"")+device.getId());
                        //for (FlowStatistics flowStatistics : device.getFlowStatistics()) {
                        //    builder.append("<p>"+flowStatistics.getFlow().getMatch()+" usage: "+Utils.printWithUnit(flowStatistics.getUsage()));
                        //}
                        return builder.toString();
                    }
                });
        mVisualizationViewer.getRenderContext().setEdgeLabelTransformer(
                new Transformer<Link, String>() {
                    @Override
                    public String transform(Link link) {
                        StringBuilder builder = new StringBuilder();
                        builder.append("<html><center>"+Utils.printWithUnit(link.getUsage()));
                        builder.append("<p>["+new DecimalFormat("#.#").format((double)link.getUsage()/(double)link.getBandwidth()*100) +"% ]");
                        //builder.append("<p>w:"+mTransformer.transform(link)+" Drops:"+link.getDropCount());
                        return builder.toString();
                    }
                });

        // Coloring
        // Nodes
        mVisualizationViewer.getRenderContext().setVertexIconTransformer(new VertexIconTransformer());
        Transformer<Device, Paint> vertexPaint = new Transformer<Device, Paint>() {
            @Override
            public Paint transform(Device device) {
                if (device.getType() == DeviceType.HOST) {
                    return Color.BLUE;
                } else if (device.getType() == DeviceType.SWITCH){
                    return Color.RED;
                } else {
                    return Color.YELLOW; //UknownType
                }

            }
        };
        mVisualizationViewer.getRenderContext().setVertexFillPaintTransformer(
                vertexPaint);
        // Edges
        final Stroke edgeStroke = new BasicStroke(8.0f);
        Transformer<Link, Stroke> edgeStrokeTransformer = new Transformer<Link, Stroke>() {
            @Override
            public Stroke transform(Link s) {
                return edgeStroke;
            }
        };
        mVisualizationViewer.getRenderContext().setEdgeStrokeTransformer(
                edgeStrokeTransformer);

        Transformer<Link, Paint> edgePaint = new Transformer<Link, Paint>() {
            @Override
            public Paint transform(Link link) {
                if (link.getUsage() >= 0.75 * link.getBandwidth()) {
                    return Color.RED;
                }
                if (link.getUsage() >= 0.25 * link.getBandwidth()) {
                    return Color.YELLOW;
                }
                return Color.GREEN;
            }
        };
        // mVisualizationViewer.getRenderContext().setEdgeFillPaintTransformer(edgePaint);
        mVisualizationViewer.getRenderContext().setEdgeDrawPaintTransformer(
                edgePaint);

        mVisualizationViewer.addPostRenderPaintable(new VisualizationViewer.Paintable(){
            int x;
            int y;
            Font font;
            FontMetrics metrics;
            int swidth;
            int sheight;

            @Override
            public void paint(Graphics g) {
                Dimension d = mVisualizationViewer.getSize();
                String str = "MaxThroughput: "+Utils.printWithUnit(getMaxThroughput());
                if(font == null) {
                    font = new Font(g.getFont().getName(), Font.BOLD, 14);
                    metrics = g.getFontMetrics(font);
                }
                swidth = metrics.stringWidth(str);
                sheight = metrics.getMaxAscent()+metrics.getMaxDescent();
                x = (d.width-swidth)/2;
                y = (int)(d.height-sheight*1.5);

                g.setFont(font);
                Color oldColor = g.getColor();
                g.setColor(Color.black);
                g.drawString(str, x, y);
                g.setColor(oldColor);
            }
            @Override
            public boolean useTransform() {
                return false;
            }
        });
        if (!GraphicsEnvironment.isHeadless()) {
            mFrame = new JFrame("NetworkMonitor");
            mFrame.setAlwaysOnTop(true);
            mFrame.setLocationByPlatform(true);
            mFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            mFrame.getContentPane().add(mVisualizationViewer);
            mFrame.pack();
            mFrame.setVisible(true);
        }
    }

    private void repaint() {
        if (!GraphicsEnvironment.isHeadless()) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    mVisualizationViewer.repaint();
                }
            });
        }
    }

    /**
     * Add edges to graph
     *
     * @param edgesMap
     */
    public void addEdges(Map<Edge, Set<Property>> edgesMap) {
        for (Edge edge : edgesMap.keySet()) {
            edgeUpdate(edge, UpdateType.ADDED, edgesMap.get(edge));
        }
        repaint();
    }

    /**
     * Apply edge update
     *
     * @param arg0
     *            - list of updates
     */
    public void edgeUpdate(List<TopoEdgeUpdate> arg0) {
        for (TopoEdgeUpdate edgeUpdate : arg0) {
            Set<Property> props = edgeUpdate.getProperty();
            UpdateType type = edgeUpdate.getUpdateType();
            Edge edge = edgeUpdate.getEdge();

            edgeUpdate(edge, type, props);
        }
        repaint();
    }

    /**
     * Applies edge update to graph
     *
     * @param edge
     *            - edge
     * @param type
     *            - type of operation
     * @param props
     *            - edge properties
     */
    private void edgeUpdate(Edge edge, UpdateType type, Set<Property> props) {
        Node headNode = edge.getHeadNodeConnector().getNode();
        Node tailNode = edge.getTailNodeConnector().getNode();
        Device headDevice = null;
        Device tailDevice = null;
        String headConnectorId = edge.getHeadNodeConnector()
                .getNodeConnectorIDString();
        String tailConnectorId = edge.getTailNodeConnector()
                .getNodeConnectorIDString();

        switch (type) {
        case ADDED:
            headDevice = addDevice(headNode);
            tailDevice = addDevice(tailNode);

            if (null == mGraph.findEdge(headDevice, tailDevice)) {
                logger.info("Adding link: {} <---> {}", headDevice, tailDevice);
                Port headPort = headDevice.createPort(headConnectorId);
                Port tailPort = tailDevice.createPort(tailConnectorId);
                Link link = new Link(edge.getHeadNodeConnector(), edge.getTailNodeConnector());
                headPort.setTargetPort(tailPort);
                headPort.setLink(link);
                tailPort.setTargetPort(headPort);
                tailPort.setLink(link);
                mGraph.addEdge(link, headDevice, tailDevice,
                        EdgeType.UNDIRECTED);
            } else {
                logger.info("Link already exists: {} <---> {}", headDevice,
                        tailDevice);
            }

            break;
        case CHANGED:
            // TODO
            logger.error("edgeUpdate type=CHANGED not implemented");
            break;
        case REMOVED:
            headDevice = getDevice(headNode);
            tailDevice = getDevice(tailNode);
            if (headDevice == null || tailDevice == null) {
                logger.warn("No devices for removed edge. Edge should also be already deleted.");
            } else {
                mGraph.removeEdge(headDevice.getLink(headConnectorId));
            }
            break;
        default:
            break;
        }
    }

    /**
     * Adds host to graph
     *
     * @param arg0
     */
    public void addHost(HostNodeConnector arg0) {
        String id = arg0.getNetworkAddressAsString();
        if (!mDevices.containsKey(id)) {
            logger.info("New host id: {}", id);
            Device device = new Device(id);
            mDevices.put(id, device);
            mGraph.addVertex(device);

            // Create link
            Device tailDevice = mDevices.get(arg0.getnodeconnectorNode()
                    .getNodeIDString());
            if (tailDevice == null) {
                tailDevice = addDevice(arg0.getnodeconnectorNode());
            }

            // TODO refactoring - makeLink or something
            String headConnectorId = id;
            String tailConnectorId = arg0.getnodeConnector()
                    .getNodeConnectorIDString();
            Port headPort = device.createPort(headConnectorId);
            Port tailPort = tailDevice.createPort(tailConnectorId);
            Link link = new Link(arg0.getnodeConnector(), arg0.getnodeConnector());
            headPort.setTargetPort(tailPort);
            headPort.setLink(link);
            tailPort.setTargetPort(headPort);
            tailPort.setLink(link);
            mGraph.addEdge(link, device, tailDevice, EdgeType.UNDIRECTED);
        }
        repaint();
    }

    /**
     * Removes host from graph
     *
     * @param arg0
     */
    public void removeHost(HostNodeConnector arg0) {
        String id = arg0.getNetworkAddressAsString();
        if (mDevices.containsKey(id)) {
            logger.info("Removing host : " + id);
            mGraph.removeVertex(mDevices.get(id));
            mDevices.remove(id);
            // TODO removing also edges related to vertex
        }
        repaint();
    }

    /**
     * Adds device to graph if doesn't exist. Otherwise returns existing one.
     *
     * @param node
     * @return device
     */
    public Device addDevice(Node node) {
        String id = node.getNodeIDString();
        if (!mDevices.containsKey(id)) {
            logger.info("New device id: {} type: {}", id, node.getType());
            Device device = new Device(node);
            mDevices.put(id, device);
            mGraph.addVertex(device);
            return device;
        }
        return mDevices.get(id);
    }

    /**
     * Returns device or null if doesn't exist.
     *
     * @param node
     * @return device
     */
    public Device getDevice(Node node) {
        return mDevices.get(node.getNodeIDString());
    }

    /**
     * Removes device and edges to it from graph
     *
     * @param node
     */
    public void removeDevice(Node node) {
        String id = node.getNodeIDString();
        if (mDevices.containsKey(id)) {
            logger.info("Removing device : " + id);
            mGraph.removeVertex(mDevices.get(id));
            mDevices.remove(id);
            // TODO removing also edges related to vertex
        }
    }

    /**
     * Sets Statistic Manager that is needed for statistics collection.
     *
     * @param statisticsManager
     */
    public void setStatisticsManager(IStatisticsManager statisticsManager) {
        this.mStatisticsManager = statisticsManager;
    }

    /**
     * Sets Switch Manager
     *
     * @param switchManager
     */
    public void setSwitchManager(ISwitchManager switchManager) {
        this.mSwitchManager = switchManager;
    }

    /**
     * Update statistics for ports based on received data.
     */
    private void processStatistics() {
        for (Node node : mSwitchManager.getNodes()) {
            List<NodeConnectorStatistics> stats = mStatisticsManager
                    .getNodeConnectorStatistics(node);

            Device device = mDevices.get(node.getNodeIDString());
            if (device == null) {
                continue;
            }
            for (NodeConnectorStatistics nodeStat : stats) {
                String connectorId = nodeStat.getNodeConnector().getNodeConnectorIDString();
                Port port = device.getPort(connectorId);
                if (port == null) {
                    // New port or most probably port not connected to another known switch
                    // So create one.
                    port = device.createPort(connectorId);
                }
                // We get in bytes, but want in bites
                //TODO move byte/bites conversion and add proper comments
                port.updateStatistics(mCurrentTime, 8*nodeStat.getTransmitByteCount(), 8*nodeStat.getReceiveByteCount(),
                        nodeStat.getReceiveDropCount(), nodeStat.getTransmitDropCount());
            }

            List<FlowOnNode> flowsOnNode = mStatisticsManager.getFlows(node);
            for (FlowOnNode flowOnNode : flowsOnNode) {
                logger.trace("Flow: {} bytes: {}", flowOnNode.getFlow().toString(), flowOnNode.getByteCount());
                FlowStatistics flowStatistics = device.getFlowStatistics(flowOnNode);
                flowStatistics.updateStatistics(mCurrentTime, flowOnNode.getByteCount());
                logger.trace("Flow usage: {}", flowStatistics.getUsage());
                //TODO remove old flows - might hook some notifications about flows
            }
        }

        //Refresh devices statistics based on update ports.
        for (Device device : mDevices.values()) {
            device.updateLinksStatistics(mCurrentTime);
        }
    }

    public List<Path<Device,Link>> getKShortestPath(Node src, Node dst, Integer K) {
        Device srcDev = mDevices.get(src.getNodeIDString());
        Device dstDev = mDevices.get(dst.getNodeIDString());
        logger.info("--- Starting K Shortest Paths ---");
        List<Path<Device,Link>> paths = kDijkstra.getPath(srcDev, dstDev, K);
        return paths;
    }

    public List<Link> getShortestPath(Node src, Node dst) {
        Device srcDev = mDevices.get(src.getNodeIDString());
        Device dstDev = mDevices.get(dst.getNodeIDString());

        List<Link> path;
        dijkstra.reset();
        path = dijkstra.getPath(srcDev, dstDev);
        return path;
    }

    public long getMaxThroughput() {
        long sum = 0;
        for (Link link : mGraph.getEdges()) {
            if (link.isHostLink()) {
                sum += link.getUsage();
            }
        }
        return sum;
    }

    public Collection<Link> getLinks() {
        return mGraph.getEdges();
    }

    public Collection<Device> getDevices() {
        return mGraph.getVertices();
    }
}
