/**
 *
 */
package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author v1t3x
 *
 */
public class ArpTable {
    private static final Logger logger = LoggerFactory.getLogger(ArpTable.class);
    private Map<String, Long> IpToMac = new HashMap<String, Long>();
    private Map<Long, String> MacToIp = new HashMap<Long, String>();
    /**
     *
     */
    public ArpTable() {
    }

    public boolean isEmpty() {
        if (IpToMac.isEmpty() && MacToIp.isEmpty()) {
            return true;
        } else if (!IpToMac.isEmpty() && ! MacToIp.isEmpty()) {
            return false;
        } else {
            logger.error("Something is wrong, one map is empty and one not.");
            logger.error(IpToMac.toString());
            logger.error(MacToIp.toString());
            return false;
        }
    }

    public void put(Long mac, String IP) {
        IpToMac.put(IP, mac);
        MacToIp.put(mac, IP);
    }

    public void remove(Long mac) {
        IpToMac.remove(getIP(mac));
        MacToIp.remove(mac);
    }

    public Long getMac(String IP) {
        return IpToMac.get(IP);
    }

    public String getIP(Long mac) {
        return MacToIp.get(mac);
    }

    public void clear() {
        IpToMac.clear();
        MacToIp.clear();
    }
}
