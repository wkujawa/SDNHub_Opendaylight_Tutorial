package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RoutesMap {
    private static final Logger logger = LoggerFactory.getLogger(RoutesMap.class);
    private Map<Long, Map<Long, List<Route>>> routesMap;
    private Map<UUID, Route> routeByUUID;

    public RoutesMap() {
        routesMap = new HashMap<Long, Map<Long,List<Route>>>();
        routeByUUID = new HashMap<UUID, Route>();
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

    public Route getRouteByUUID(UUID id) {
        return routeByUUID.get(id);
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
        // Mapping by UUIDs
        for (Route route : routes) {
            routeByUUID.put(route.getId(), route);
        }
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
            // Removing from by UUID map
            for(List<Route> routes :srcMap.values()) {
                for (Route route: routes) {
                    routeByUUID.remove(route.getId());
                }
            }
            srcMap.remove(dstMAC);
        }
        if (dstMap != null) {
            // Removing from by UUID map
            for(List<Route> routes :dstMap.values()) {
                for (Route route: routes) {
                    routeByUUID.remove(route.getId());
                }
            }
            dstMap.remove(srcMAC);
        }
    }

    /**
     * Remove information about flow from route.
     * @param flow that was deleted from switch
     */
    public void removeFlow(Flow flow) {
        MatchField srcField = flow.getMatch().getField(MatchType.DL_SRC);
        MatchField dstField = flow.getMatch().getField(MatchType.DL_DST);

        if (srcField.isValid() && dstField.isValid()) {
            byte[] srcMAC = (byte[]) srcField.getValue();
            byte[] dstMAC = (byte[]) dstField.getValue();
            List<Route> routes = getRoutes(srcMAC, dstMAC);
            if (!routes.isEmpty()) {
                for (Route route : routes) {
                    route.removeFlow(flow);
                }
            } else {
                logger.warn("No routes between {} and {}", Utils.mac2str(srcMAC), Utils.mac2str(dstMAC));
            }
        } else {
            logger.error("Cannot remove flow from routes map. Flow doesn't have DL_SRC or DL_DST in Match");
        }
    }
}
