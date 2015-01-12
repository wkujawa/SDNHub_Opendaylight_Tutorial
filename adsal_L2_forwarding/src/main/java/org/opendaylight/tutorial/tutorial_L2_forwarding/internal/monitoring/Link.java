package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.text.DecimalFormat;

public class Link {
	private final String mId;
	private final Port mParent;
	private final Port mTarget;
	private long mUsage;
	private long mUpdateTime;
	private long mBandwidth;
	
	public Link(String id, Port parent, Port target) {
		mId = id;
		mParent = parent;
		mTarget = target;
	    //TODO workaround hardcoded 100Mb/s link bw.
        // That cannot be gathered from parameters because in VETH it is hardcoded to 10Gb/s0
		mBandwidth = Utils.MB*100;
	}
	
	public String getId() {
		return mId;
	}

	@Override
	public String toString() {
	    return "["+Utils.printWithUnit(mUsage)+"] ["
	            + new DecimalFormat("#.#").format((double)mUsage/(double)mBandwidth*100) +"% ]";
	}
	
	public Port getParent() {
		return mParent;
	}

	public Port getTarget() {
		return mTarget;
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
