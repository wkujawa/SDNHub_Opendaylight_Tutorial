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
