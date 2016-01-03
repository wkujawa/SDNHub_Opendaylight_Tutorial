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
import org.opendaylight.controller.sal.match.Match;

public class LogicalFlow {
    protected final int id;
    protected final Match match;
    protected final short priority;
    protected final String srcIP;
    protected final String dstIP;
    protected int queue;
    //TODO add stats

    public LogicalFlow(Match match, String srcIP, String dstIP, int id, short priority) {
        this.id = id;
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.match = match;
        this.priority = priority;
        this.queue = 0;
    }

    public int getId() {
        return id;
    }

    public Match getMatch() {
        return match;
    }

    public String getSrcIP() {
        return srcIP;
    }

    public String getDstIP() {
        return dstIP;
    }

    public int getQueue() {
        return queue;
    }

    public void setQueue(int queue) {
        this.queue = queue;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + id;
        result = prime * result + queue;
        result = prime * result + ((match == null) ? 0 : match.hashCode());
        return result;
    }

    public boolean equals(Match match) {
        if (this.match.equals(match))
            return true;
        return false;
    }

    public boolean equals(Flow flow) {
        if (flow == null) {
            return false;
        }
        if (!match.equals(flow.getMatch()))
            return false;
        if (priority != flow.getPriority())
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "LogicalFlow [id=" + id + ", match=" + match + ", priority="
                + priority + ", srcIP=" + srcIP + ", dstIP=" + dstIP + ", queue="+queue+"]";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        LogicalFlow other = (LogicalFlow) obj;
        if (id != other.id)
            return false;
        if (queue != other.queue)
            return false;
        if (match == null) {
            if (other.match != null)
                return false;
        } else if (!match.equals(other.match))
            return false;
        return true;
    }

}
