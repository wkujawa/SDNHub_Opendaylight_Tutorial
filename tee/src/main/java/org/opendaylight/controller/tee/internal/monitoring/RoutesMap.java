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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RoutesMap {
    private static final Logger logger = LoggerFactory.getLogger(RoutesMap.class);
    private Map<Long, Map<Long, List<Route>>> routesMap;
    private Map<Integer, Route> routeById;

    public RoutesMap() {
        routesMap = new ConcurrentHashMap<Long, Map<Long,List<Route>>>();
        routeById = new ConcurrentHashMap<Integer, Route>();
    }

    public boolean isEmpty() {
        if (routeById.isEmpty() && routesMap.isEmpty()) {
            return true;
        } else if (!routeById.isEmpty() && !routesMap.isEmpty()) {
            return false;
        } else {
            logger.error("Something wrong, one map is empty and one is not");
            logger.error(routeById.toString());
            logger.error(routesMap.toString());
            return false;
        }
    }

    public List<Route> getRoutes(byte[] srcMAC) {
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        return getRoutes(srcMAC_val);
    }

    public List<Route> getRoutes(long srcMAC) {
        Map<Long, List<Route>> srcMap = routesMap.get(srcMAC);
        List<Route> routes = new LinkedList<Route>();
        if (srcMap == null) {
            return routes;
        } else {
            for (List<Route> r : srcMap.values()) {
                routes.addAll(r);
            }
        }
        return routes;
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
        logger.debug("Looking for best path:");
        for (Route route : routes) {
            route.evaluate();
            logger.debug(route.toString());
        }
        Collections.sort(routes);
        return routes.get(0);
    }

    public Route getRouteById(int id) {
        return routeById.get(id);
    }

    public List<Route> getAllRoutes() {
        List<Route> allRoutes = new ArrayList<Route>();
        for (Map<Long, List<Route>> map : routesMap.values()) {
            for (List<Route> routes : map.values()) {
                allRoutes.addAll(routes);
            }
        }
        return allRoutes;
    }

    public void addRoutes(List<Route> routes, byte[] srcMAC, byte[] dstMAC) {
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        addRoutes(routes, srcMAC_val, dstMAC_val);
    }

    public void addRoutes(List<Route> routes, long srcMAC, long dstMAC) {

        Map<Long,List<Route>> srcMap = routesMap.get(srcMAC);
        if (srcMap == null) {
            srcMap = new HashMap<Long,List<Route>>();
            routesMap.put(srcMAC, srcMap);
        }

        if (srcMap.containsKey(dstMAC)) {
            logger.warn("There are already routes for {}->{}",
                    Utils.mac2str(srcMAC), Utils.mac2str(dstMAC));
            logger.warn("Replacing {} with {}", srcMap.get(dstMAC), routes);
        }

        srcMap.put(dstMAC, routes);
        // Mapping by IDs
        for (Route route : routes) {
            routeById.put(route.getId(), route);
        }
    }

    /**
     * Remove routes from and to host.
     * @param srcMAC - MAC address of host
     */
    public void removeRoutes(byte[] srcMAC) {
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        removeRoutes(srcMAC_val);
    }

    /**
     * Remove routes from and to host.
     * @param srcMAC - MAC address of host
     */
    public void removeRoutes(long srcMAC) {
        logger.info("Removing routes connecting with {}", Utils.mac2str(srcMAC));
        // Clear all routes from src
        Map<Long, List<Route>> srcMap = routesMap.get(srcMAC);
        if (srcMap != null) {
            // Removing from by IDs map
            for(List<Route> routes :srcMap.values()) {
                for (Route route: routes) {
                    routeById.remove(route.getId());
                }
            }
            routesMap.remove(srcMAC);
        }

        //Clear all routes to src
        for (Long mac : routesMap.keySet()) {
            if (routesMap.get(mac).containsKey(srcMAC)) {
                removeRoutes(mac, srcMAC);
            }
        }
    }

    public void removeRoutes(byte[] srcMAC, byte[] dstMAC) {
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        removeRoutes(srcMAC_val, dstMAC_val);
    }

    public void removeRoutes(long srcMAC, long dstMAC) {
        Map<Long, List<Route>> srcMap = routesMap.get(srcMAC);
        if (srcMap != null) {
            // Removing from by IDs map
            for(List<Route> routes :srcMap.values()) {
                for (Route route: routes) {
                    routeById.remove(route.getId());
                }
            }
            srcMap.remove(dstMAC);
            if (srcMap.isEmpty()) {
                routesMap.remove(srcMAC);
            }
        }
    }

    /**
     * Remove information about flow from route.
     * @param flow that was deleted from switch
     */
    public void removeFlow(Flow flow) {
        MatchField srcField = flow.getMatch().getField(MatchType.DL_SRC);
        MatchField dstField = flow.getMatch().getField(MatchType.DL_DST);

        if (srcField == null || dstField == null) {
            // It is Flow leading to host, no information is stored about it
            return;
        }

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
