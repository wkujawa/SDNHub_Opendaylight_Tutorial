package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Paint;
import java.awt.Stroke;
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
import org.opendaylight.controller.sal.topology.TopoEdgeUpdate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.uci.ics.jung.algorithms.layout.FRLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.UndirectedSparseMultigraph;
import edu.uci.ics.jung.graph.util.EdgeType;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.DefaultModalGraphMouse;
import edu.uci.ics.jung.visualization.control.ModalGraphMouse.Mode;
import edu.uci.ics.jung.visualization.decorators.ToStringLabeller;
import edu.uci.ics.jung.visualization.renderers.Renderer;

public class NetworkMonitor {
    private static final Logger logger = LoggerFactory
            .getLogger(NetworkMonitor.class);
    
	private final int UPDATE_INTERVAL = 10000;
	private MonitorThread mWorker;
	
	private JFrame mFrame;
	private Graph<Device, Link> mGraph;
	private Layout<Device, Link> mVisualizer;
	private VisualizationViewer<Device, Link> mVisualizationViewer;
	
//	private Topology mPreviousTopology;
//	private Topology mCurrentTopology;
	
//	private AllPortStatistics mPreviousStatistics;
	private long mPreviousTime;
//	private AllPortStatistics mCurrentStatistics;
	private long mCurrentTime;

	
	/**
	 * Collection of detected devices.
	 */
	private  final HashMap<String, Device> mDevices;
	
	private class MonitorThread extends Thread {
		@Override
		public void run() {
			super.run();
			logger.info("Monitor thread started.");
			while (!isInterrupted()) {
/*				mPreviousTopology = mCurrentTopology;
				mCurrentTopology = getTopology();
				
				mPreviousStatistics = mCurrentStatistics;
				mPreviousTime = mCurrentTime;
				mCurrentStatistics = getStatistics();
				mCurrentTime = System.currentTimeMillis();
*/						
				// !!!! DEBUG
//				System.out.println("INFO: add.");
//				mGraph.addVertex(new Device("12", "MY"));
				// !!!! DEBUG

				processStatistics();
				
				repaint();
				
/*				//Debug
				printTopology(mCurrentTopology);
				printStatistics(mCurrentStatistics);
				printDevicesInfo();
*/				//Debug
				
				try {
					Thread.sleep(UPDATE_INTERVAL);
				} catch (InterruptedException e) {
                    //Closing thread
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
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				initGraphView();				
			}
			
		});
		
		init();	
	}
	
	private void init() {
		mWorker = new MonitorThread();
		mWorker.start();
	}
	
	public void stop() {
	    mWorker.interrupt();
	    mFrame.setVisible(false);
	    mFrame.dispose();
	}
	
	private void initGraphView() {
		// The Layout<V, E> is parameterized by the vertex and edge types
		mVisualizer = new FRLayout<Device, Link>(mGraph);
		mVisualizer.setSize(new Dimension(300,300)); // sets the initial size of the space
		mVisualizationViewer = new VisualizationViewer<Device, Link>(mVisualizer);
		// BasicVisualizationServer<Device, Link> vv = new BasicVisualizationServer<Device, Link>(layout);
		mVisualizationViewer.setPreferredSize(new Dimension(650,650)); //Sets the viewing area size
		
		DefaultModalGraphMouse<Device, Link> graphMouse = new DefaultModalGraphMouse<Device, Link>();
		graphMouse.setMode(Mode.PICKING);
		mVisualizationViewer.setGraphMouse(graphMouse);
		
		mVisualizationViewer.getRenderer().getVertexLabelRenderer().setPosition(Renderer.VertexLabel.Position.CNTR);
		mVisualizationViewer.getRenderContext().setVertexLabelTransformer(new ToStringLabeller<Device>());	
		mVisualizationViewer.getRenderContext().setEdgeLabelTransformer(new ToStringLabeller<Link>());

		//Coloring
		//Nodes
        Transformer<Device,Paint> vertexPaint = new Transformer<Device,Paint>() {
            public Paint transform(Device device) {
            	if (device.getType().equals("HOST")) {
            		return Color.BLUE;
            	} else {
            		return Color.RED;
            	}
            	
            }
        };
        mVisualizationViewer.getRenderContext().setVertexFillPaintTransformer(vertexPaint);
        //Edges
        final Stroke edgeStroke = new BasicStroke(8.0f);
        Transformer<Link, Stroke> edgeStrokeTransformer = new Transformer<Link, Stroke>() {
            public Stroke transform(Link s) {
                return edgeStroke;
            }
        };
        mVisualizationViewer.getRenderContext().setEdgeStrokeTransformer(edgeStrokeTransformer);
        
        Transformer<Link,Paint> edgePaint = new Transformer<Link,Paint>() {
            public Paint transform(Link link) {
            	if (link.getUsage() >= 50*Utils.MB) {
            		return Color.RED;
            	}
            	if (link.getUsage() >= Utils.MB) {
            		return Color.YELLOW;
            	}
            	return Color.GREEN;
            }
        };
        //mVisualizationViewer.getRenderContext().setEdgeFillPaintTransformer(edgePaint);
        mVisualizationViewer.getRenderContext().setEdgeDrawPaintTransformer(edgePaint);
        
		mFrame = new JFrame("NetworkMonitor");
		mFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mFrame.getContentPane().add(mVisualizationViewer);
		mFrame.pack();
		mFrame.setVisible(true);
	}
	
	private void repaint() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                mVisualizationViewer.repaint();     
            }
        });
	}
	
	/**
	 * Add edges to graph
	 * @param edgesMap
	 */
	public void addEdges(Map<Edge, Set<Property>> edgesMap) {
	    for(Edge edge : edgesMap.keySet()) {
	        edgeUpdate(edge, UpdateType.ADDED, edgesMap.get(edge));
	    }
	    repaint();
	}
	
	/**
	 * Apply edge update
	 * @param arg0 - list of updates
	 */
	public void edgeUpdate(List<TopoEdgeUpdate> arg0) {
	    for (TopoEdgeUpdate edgeUpdate : arg0) {
            Set<Property> props =  edgeUpdate.getProperty();
            UpdateType type = edgeUpdate.getUpdateType();
            Edge edge = edgeUpdate.getEdge();
            
            edgeUpdate(edge, type, props);
        }
	    repaint();
	}
	
	/**
	 * Applies edge update to graph
	 * @param edge - edge
	 * @param type - type of operation
	 * @param props - edge properties
	 */
	private void edgeUpdate(Edge edge, UpdateType type, Set<Property> props) {
        Node headNode = edge.getHeadNodeConnector().getNode();
        Node tailNode = edge.getTailNodeConnector().getNode();
        
        switch (type) {
        case ADDED:
            addDevice(headNode);
            addDevice(tailNode);
            
            Device headDevice = mDevices.get(headNode.getNodeIDString());
            Device tailDevice = mDevices.get(tailNode.getNodeIDString());
            if( null==mGraph.findEdge(headDevice, tailDevice) ) {
                logger.info("Adding link: {} <---> {}",headDevice, tailDevice);
                String headConnectorId = edge.getHeadNodeConnector().getNodeConnectorIDString();
                String tailConnectorId = edge.getTailNodeConnector().getNodeConnectorIDString();
                Port headPort = headDevice.createPort(headConnectorId);
                Port tailPort = tailDevice.createPort(tailConnectorId);
                Link link = new Link(headConnectorId+":"+tailConnectorId,
                        headPort,
                        tailPort);
                headPort.setTargetPort(tailPort);
                headPort.setLink(link);
                tailPort.setTargetPort(headPort);
                tailPort.setLink(link);
                mGraph.addEdge(link, headDevice, tailDevice, EdgeType.UNDIRECTED);
            } else {
                logger.info("Link already exists: {} <---> {}",headDevice, tailDevice);
            }
            
            break;
        case CHANGED:
            // TODO
            logger.error("edgeUpdate type=CHANGED not implemented");
            break;
        case REMOVED:
            //TODO just remove edge
            //removeDevice(headNode);
            //removeDevice(tailNode);
            break;
        default:
            break;
        }
	}
	
	/**
	 * Adds host to graph
	 * @param arg0
	 */
    public void addHost(HostNodeConnector arg0) {
        String id = arg0.getNetworkAddressAsString();
        if (!mDevices.containsKey(id)) {
            logger.info("New host id: {}",id);
            Device device = new Device(id, "HOST");
            mDevices.put(id, device);
            mGraph.addVertex(device);
            
            // Create link
            Device tailDevice = mDevices.get(arg0.getnodeconnectorNode().getNodeIDString());
            String headConnectorId = id;
            String tailConnectorId = arg0.getnodeConnector().getNodeConnectorIDString();
            Port headPort = device.createPort(headConnectorId);
            Port tailPort = tailDevice.createPort(tailConnectorId);
            Link link = new Link(headConnectorId+":"+tailConnectorId,
                    headPort,
                    tailPort);
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
     * @param arg0
     */
    public void removeHost(HostNodeConnector arg0) {
        String id = arg0.getNetworkAddressAsString();
        if (mDevices.containsKey(id)) {
            logger.info("Removing host : "+id);
            mGraph.removeVertex(mDevices.get(id));
            mDevices.remove(id);
            //TODO removing also edges related to vertex
        }
        repaint();
    }
	
	/**
	 * Adds device to graph
	 * @param node
	 * @return true if node added, false if node already exists
	 */
	private boolean addDevice(Node node) {
		String id = node.getNodeIDString();
		if (!mDevices.containsKey(id)) {
			logger.info("New device id: {} type: {}",id, node.getType());
			Device device = new Device(id, node.getType());
			mDevices.put(id, device);
			mGraph.addVertex(device);
			return true;
		}
		return false;
	}
	
	   /**
     * Removes device and edges to it from graph
     * @param node
     */
    private void removeDevice(Node node) {
        String id = node.getNodeIDString();
        if (mDevices.containsKey(id)) {
            logger.info("Removing device : "+id);
            mGraph.removeVertex(mDevices.get(id));
            mDevices.remove(id);
            //TODO removing also edges related to vertex
        }
    }
	
	/**
	 * Update statistics for ports based on received data.
	 */
	private void processStatistics() {
/*		//Process statistics and save it in ports.
		for (PortStatistics portStat : mCurrentStatistics.getPortStatistics()) {
			Device device = mDevices.get(portStat.getNode().getNodeIDString());
			for (NodeConnectorStatistics nodeStat : portStat.getPortStatistic()) {
				String connectorId = nodeStat.getNodeConnector().getNodeConnectorIDString();
				Port port = device.getPort(connectorId);
				if (port == null) {
					// New port or most probably port not connected to another known switch
					// So create one.
					port = device.createPort(connectorId);
				}
				
				port.updateStatistics(mCurrentTime, nodeStat.getTransmitBytes(), nodeStat.getReceiveBytes());
				
				//Add unknown endpoints for ports // TODO later some of them might be detected as some kind of device.
				if (port.getTargetPort() == null && !connectorId.equals("0")) { // Don't know what is port "0" - ignoring it
					Device fakeDev = new Device(connectorId, Device.UNKNOWN_DEV_TYPE);
					Port fakePort = fakeDev.createPort(Port.FAKE_PORT);
					Link link = new Link(connectorId+":"+fakePort.getPortId(),
							port,
							fakePort);
					port.setTargetPort(fakePort);
					port.setLink(link);
					fakePort.setTargetPort(port);
					fakePort.setLink(link);
					mGraph.addVertex(fakeDev);
					mGraph.addEdge(link, device, fakeDev, EdgeType.UNDIRECTED);
				}
			}
		}
		
		//Refresh devices statistics based on update ports.
		for (Device device : mDevices.values()) {
			device.updateLinksStatistics(mCurrentTime);
		}*/
	}
	
/*	private Topology getTopology() {
		// TODO use MediaType.APPLICATION_XML_TYP in requests, json not working - no annotations for json in rest-api jars ?
		return mTarget.path("/controller/nb/v2/topology/default").request(MediaType.APPLICATION_XML_TYPE).get(Topology.class);
	
}
	
	private void printTopology(Topology topo) {
		System.out.println("*** Topology ***");
		System.out.println("Edges : " + topo.getEdgeProperties().size()); //TODO check for nullptr when empty topo
		for (EdgeProperties edgeProp : topo.getEdgeProperties()) {
			Edge edge = edgeProp.getEdge();
			System.out.println("Edge : "+edge.getHeadNodeConnector().getNodeConnectorIDString() + " --- " + edge.getTailNodeConnector().getNodeConnectorIDString());
		}
		System.out.println("****************");
	}
	
	private AllPortStatistics getStatistics() {
		return mTarget.path("/controller/nb/v2/statistics/default/port").request(MediaType.APPLICATION_XML_TYPE).get(AllPortStatistics.class);
		
	}
	
	private void printStatistics(AllPortStatistics statistics) {
		System.out.println("*** Statistics ***");
		for (PortStatistics portStat : statistics.getPortStatistics()) {
			System.out.println("Node : " + portStat.getNode().getNodeIDString());
			for ( NodeConnectorStatistics nodeStat : portStat.getPortStatistic()) {
				System.out.println("Connector : " + nodeStat.getNodeConnector().getNodeConnectorIDString() 
						+ " recvBytes: " + nodeStat.getReceiveBytes()
						+ " sendBytes: " + nodeStat.getTransmitBytes());
			}
		}
		System.out.println("******************");
	}

	private void printDevicesInfo() {
		System.out.println("*** Devices Info ***");
		for (Device device : mDevices.values()) {
			System.out.println(device.debugInfo());
		}
		System.out.println("********************");
	}
*/
}
