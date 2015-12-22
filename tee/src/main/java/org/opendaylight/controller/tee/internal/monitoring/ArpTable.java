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
/**
 *
 */
package org.opendaylight.controller.tee.internal.monitoring;

import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author v1t3x
 *
 */
public class ArpTable {
    private static final Logger logger = LoggerFactory.getLogger(ArpTable.class);
    private Map<String, Long> IpToMac = new ConcurrentHashMap<String, Long>();
    private Map<Long, String> MacToIp = new ConcurrentHashMap<Long, String>();
    private Map<Long, HostNodeConnector> MacToNodeConnector = new ConcurrentHashMap<Long, HostNodeConnector>();

    /**
     *
     */
    public ArpTable() {
    }

    public boolean isEmpty() {
        if (IpToMac.isEmpty() && MacToIp.isEmpty()) {
            return true;
        } else if (!IpToMac.isEmpty() && !MacToIp.isEmpty()) {
            return false;
        } else {
            logger.error("Something is wrong, one map is empty and one not.");
            logger.error(IpToMac.toString());
            logger.error(MacToIp.toString());
            return false;
        }
    }

    public void put(Long mac, String IP, HostNodeConnector connector) {
        IpToMac.put(IP, mac);
        MacToIp.put(mac, IP);
        MacToNodeConnector.put(mac, connector);
    }

    public void remove(Long mac) {
        IpToMac.remove(getIP(mac));
        MacToIp.remove(mac);
        MacToNodeConnector.remove(mac);
    }

    public Long getMac(String IP) {
        return IpToMac.get(IP);
    }

    public String getIP(Long mac) {
        return MacToIp.get(mac);
    }

    public HostNodeConnector getNodeConnector(Long mac) {
        return MacToNodeConnector.get(mac);
    }

    public void clear() {
        IpToMac.clear();
        MacToIp.clear();
        MacToNodeConnector.clear();
    }

    public void debugPrint() {
        logger.info("--------------IpToMac--------------");
        for (Entry<String, Long> entry : IpToMac.entrySet()) {
            logger.info(">> "+entry.getKey().toString()+" : "+Utils.mac2str(entry.getValue()));
        }
        logger.info("--------------MacToIP--------------");
        for (Entry<Long, String> entry : MacToIp.entrySet()) {
            logger.info(">> "+Utils.mac2str(entry.getKey())+" : "+entry.getValue().toString());
        }
    }
}
