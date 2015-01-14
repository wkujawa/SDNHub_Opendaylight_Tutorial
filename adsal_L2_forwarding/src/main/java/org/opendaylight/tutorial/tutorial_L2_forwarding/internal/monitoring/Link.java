package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.text.DecimalFormat;

import org.opendaylight.controller.sal.core.NodeConnector;

public class Link {
	private final NodeConnector mSourceConnector;
	private final NodeConnector mDestinationConnector;
	private long mUsage;
	private long mUpdateTime;
	private long mBandwidth;
	
	public Link(NodeConnector src, NodeConnector dst) {
		mSourceConnector = src;
		mDestinationConnector = dst;
	    //TODO workaround hardcoded 100Mb/s link bw.
        // That cannot be gathered from parameters because in VETH it is hardcoded to 10Gb/s0
		mBandwidth = Utils.MB*100;
	}

	@Override
	public String toString() {
	    return "["+Utils.printWithUnit(mUsage)+"] ["
	            + new DecimalFormat("#.#").format((double)mUsage/(double)mBandwidth*100) +"% ]";
	}
	
	public NodeConnector getSourceConnector() {
		return mSourceConnector;
	}

	public NodeConnector getDestinationConnector() {
		return mDestinationConnector;
	}

	public long getUsage() {
		return mUsage;
	}

	public long getUpdateTime() {
		return mUpdateTime;
	}

	public long getBandwidth() {
        return mBandwidth;
    }

    public void setBandwidth(long bandwidth) {
        this.mBandwidth = bandwidth;
    }

    protected void updateStatistic(long timestamp, long usage) {
		mUpdateTime = timestamp;
		mUsage = usage;
	}
}
