package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

public class Link {
	private final String mId;
	private final Port mParent;
	private final Port mTarget;
	private long mUsage;
	private long mUpdateTime;
	
	public Link(String id, Port parent, Port target) {
		mId = id;
		mParent = parent;
		mTarget = target;
	}
	
	public String getId() {
		return mId;
	}

	@Override
	public String toString() {
		return "["+Utils.printWithUnit(mUsage)+"]";
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

	protected void updateStatistic(long timestamp, long usage) {
		mUpdateTime = timestamp;
		mUsage = usage;
	}
}
