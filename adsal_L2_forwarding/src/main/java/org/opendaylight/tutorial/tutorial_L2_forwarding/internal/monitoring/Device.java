package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.HashMap;
import java.util.Map;

public class Device {
	public final static String UNKNOWN_DEV_TYPE = "Unknow";
	private String mId;
	private String mType;
	private Map<String,Port> mPorts;
	
	public Device(String id, String type) {
		mId = id;
		mType = type;
		mPorts = new HashMap<String,Port>();
	}
	
	public String getId() {
		return mId;
	}

	public String getType() {
		return mType;
	}
	
	/**
	 * Returns port for given id.
	 * @param portId - port ID
	 * @return port handle, null if don't exist.
	 */
	public Port getPort(String portId) {
		return mPorts.get(portId);
	}

	/**
	 * Creates port if does not exist.
	 * @param portId - port ID
	 * @return port - handle
	 */
	public Port createPort(String portId) {
		if (mPorts.containsKey(portId)) {
			return mPorts.get(portId);
		} else {
			Port port = new Port(this, portId);
			mPorts.put(portId, port);
			return port;
		}
	}
	
	public void updateLinksStatistics(long time){
		for (Port port : mPorts.values()) {
			Link link = port.getLink();
			if (link != null) {
				if (time > link.getUpdateTime()) {
					// First device makes update
					link.updateStatistic(time, port.getDataRate());
				} else if (time == link.getUpdateTime()) {
					// Second side of link makes update
					// Statistic of link as average of both
					long usage = (link.getUsage() + port.getDataRate()) / 2;
					link.updateStatistic(time, usage);
				}
			}
		}
	}
	
	// DEBUG
	public String debugInfo() {
		StringBuilder builder = new StringBuilder();
		builder.append("Device ["+mId+" type: "+mType+"\n");
		for (Port port : mPorts.values()) {
			builder.append(port.toString()+"\n");
		}
		return builder.toString();
	}
	
	@Override
	public String toString() {
		return mType+":"+mId;
	}
}
