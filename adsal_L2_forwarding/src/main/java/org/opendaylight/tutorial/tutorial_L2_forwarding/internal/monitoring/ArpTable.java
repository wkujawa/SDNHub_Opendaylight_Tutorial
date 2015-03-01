/**
 * 
 */
package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.HashMap;
import java.util.Map;

/**
 * @author v1t3x
 *
 */
public class ArpTable {
    private Map<String, Long> IpToMac = new HashMap<String, Long>();
    private Map<Long, String> MacToIp = new HashMap<Long, String>();
    /**
     * 
     */
    public ArpTable() {
    }
    
    public void put(Long mac, String IP) {
        IpToMac.put(IP, mac);
        MacToIp.put(mac, IP);
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
