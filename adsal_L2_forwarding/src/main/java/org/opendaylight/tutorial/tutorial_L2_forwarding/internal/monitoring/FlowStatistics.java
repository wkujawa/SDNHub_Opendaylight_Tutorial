package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import org.opendaylight.controller.sal.flowprogrammer.Flow;

public class FlowStatistics {
    Flow mFlow;
    private long mUsage;
    private long mByteCount;
    private long mTimeStamp;

    public FlowStatistics(Flow flow, long byteCount) {
        mFlow = flow;
        mByteCount = byteCount;
        mTimeStamp = System.currentTimeMillis();
    }

    protected void updateStatistics(long timestamp, long byteCount) {
        if (getTimeDiffSeconds(timestamp) == 0) {
            mUsage = 0;
        } else {
            mUsage = (long) ((byteCount - mByteCount) / getTimeDiffSeconds(timestamp));
        }
        mTimeStamp = timestamp;
        mByteCount = byteCount;
    }

    public long getUsage() {
        return mUsage*8; //bites
    }

    public Flow getFlow() {
        return mFlow;
    }

    private double getTimeDiffSeconds(long timestamp) {
        return (timestamp - mTimeStamp) / 1000.0;
    }
}
