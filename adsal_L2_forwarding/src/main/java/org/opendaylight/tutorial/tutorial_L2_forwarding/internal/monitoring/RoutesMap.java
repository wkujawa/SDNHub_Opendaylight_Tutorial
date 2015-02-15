package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.opendaylight.controller.sal.packet.BitBufferHelper;

public class RoutesMap {
    private Map<Long, Map<Long, List<Route>>> routesMap;
    
    public RoutesMap() {
        routesMap = new HashMap<Long, Map<Long,List<Route>>>();
    }
    
    public List<Route> getRoutes(byte[] srcMAC, byte[] dstMAC) {
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        return getRoutes(srcMAC_val, dstMAC_val);
    }
    
    public List<Route> getRoutes(long srcMAC, long dstMAC) {
        Map<Long, List<Route>> srcMap = routesMap.get(srcMAC);
        if (srcMap == null) {
            return new LinkedList<Route>();
        } else {
            List<Route> routes = srcMap.get(dstMAC);
            if (routes == null) {
                return new LinkedList<Route>();
            } else {
                return routes;
            }
        }
    }
    
    public Route getActiveRoute(byte[] srcMAC, byte[] dstMAC) {
        List<Route> routes = getRoutes(srcMAC, dstMAC);
        for (Route route :  routes) {
            if (route.isActive()) {
                return route;
            }
        }
        assert false : "No active route";
        return null;
    }
    
    public Route getBestRoute(byte[] srcMAC, byte[] dstMAC) {
        List<Route> routes = getRoutes(srcMAC, dstMAC);
        for (Route route : routes) {
            route.evaluate();
        }
        Collections.sort(routes);
        return routes.get(0);
    }
    
    public void addRoutes(List<Route> routes, byte[] srcMAC, byte[] dstMAC) {
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        addRoutes(routes, srcMAC_val, dstMAC_val);
    }
    
    public void addRoutes(List<Route> routes, long srcMAC, long dstMAC) {
        Map<Long,List<Route>> dstMap = new HashMap<Long,List<Route>>();
        Map<Long,List<Route>> srcMap = new HashMap<Long,List<Route>>();
        dstMap.put(dstMAC, routes);
        srcMap.put(srcMAC, routes);
        routesMap.put(srcMAC, dstMap);
        routesMap.put(dstMAC, srcMap);
    }
    
    public void removeRoutes(byte[] srcMAC, byte[] dstMAC) {
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        removeRoutes(srcMAC_val, dstMAC_val);
    }
    
    public void removeRoutes(long srcMAC, long dstMAC) {
        Map<Long, List<Route>> srcMap = routesMap.get(srcMAC);
        Map<Long, List<Route>> dstMap = routesMap.get(srcMAC);
        if (srcMap != null) {
            srcMap.remove(dstMAC);
        }
        if (dstMap != null) {
            dstMap.remove(srcMAC);
        }
    }
}
