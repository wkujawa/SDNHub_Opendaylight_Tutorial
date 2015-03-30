package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

public class Port {
    public final static String FAKE_PORT = "FakePort";
    private String mPortId;
    private Device mParent;
    private Port mTargetPort;
    private Link mLink;

    //////////////////////////
    // Statistic fields
    //////////////////////////
    private long mLastTimestamp;
    private long mPreviousTimestamp;

    private long mLastReceived;
    private long mLastSent;
    private long mLastDropReceive;
    private long mLastDropTransmit;
    private long mPreviousReceived;
    private long mPreviousSent;
    private long mPreviousDropReceive;
    private long mPreviousDropTransmit;

    public Port(Device parent, String portId) {
        mParent = parent;
        mPortId = portId;
        mTargetPort = null;
        mLink = null;
    }

    @Override
    public String toString() {
        String target = mTargetPort != null ? mTargetPort.getPortId()
                : "Unknown";
        return "Port [ " + mPortId + " -> " + target + " ] " + "S: "
                + getSendingRate() + " / R: " + getReceivingRate() + " Drop: "
                + getDropCount();
    }

    public String getPortId() {
        return mPortId;
    }

    public long getSendingRate() {
        if (getTimeDiffSeconds() == 0) {
            return 0;
        }
        return (long) ((mLastSent - mPreviousSent) / getTimeDiffSeconds());
    }

    public long getReceivingRate() {
        if (getTimeDiffSeconds() == 0) {
            return 0;
        }
        return (long) ((mLastReceived - mPreviousReceived) / getTimeDiffSeconds());
    }

    public long getDataRate() {
        return getSendingRate() + getReceivingRate();
    }

    public Device getDevice() {
        return mParent;
    }

    public Port getTargetPort() {
        return mTargetPort;
    }

    public Link getLink() {
        return mLink;
    }

    public long getDropCount() {
        return (mLastDropReceive - mPreviousDropReceive)
                + (mLastDropTransmit - mPreviousDropTransmit);
    }

    protected void setTargetPort(Port targetPort) {
        this.mTargetPort = targetPort;
    }

    protected void setLink(Link link) {
        this.mLink = link;
    }

    protected void updateStatistics(long timestamp, long sent, long received,
            long dropReceived, long dropTransmit) {
        mPreviousTimestamp = mLastTimestamp;
        mPreviousSent = mLastSent;
        mPreviousReceived = mLastReceived;
        mPreviousDropReceive = mLastDropReceive;
        mPreviousDropTransmit = mLastDropTransmit;

        mLastTimestamp = timestamp;
        mLastSent = sent;
        mLastReceived = received;
        mLastDropReceive = dropReceived;
        mLastDropTransmit = dropTransmit;
    }

    private double getTimeDiffSeconds() {
        return (mLastTimestamp - mPreviousTimestamp) / 1000.0;
    }

}
