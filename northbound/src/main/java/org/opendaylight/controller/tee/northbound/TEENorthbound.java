package org.opendaylight.controller.tee.northbound;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.northbound.commons.RestMessages;
import org.opendaylight.controller.northbound.commons.exception.ServiceUnavailableException;
import org.opendaylight.controller.sal.utils.ServiceHelper;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.ITEE;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Device;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Link;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.LogicalFlow;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring.Route;

@Path("/")
public class TEENorthbound {
    /**
     * Just simple test
     *
     * @return - test message
     */
    @Path("/test")
    @GET
    public Response getTest() {
        return Response.ok(new String("Simple test :)")).build();
    }

    /**
     * Get detected hosts
     *
     * @return - list of hosts
     */
    @Path("/hosts")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public Set<Host> getHosts() {
        ITEE tee = getTEE();
        Set<Host> set = new HashSet<Host>();
        for(HostNodeConnector hostConnector : tee.getAllHosts()) {
            set.add(new Host(hostConnector));
        }
        return set;
    }

    /**
     * Get active links (edges)
     *
     * @return - list of links
     */
    @Path("/links")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public Collection<Link> getLinks() {
        ITEE tee = getTEE();
        return tee.getLinks();
    }

    /**
     * Get active devices (switches)
     *
     * @return - list of devices
     */
    @Path("/devices")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public Collection<Device> getDevices() {
        ITEE tee = getTEE();
        return tee.getDevices();
    }

    /**
     * Get all logical flows
     *
     * @return - list of logical flows
     */
    @Path("/flows")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public Collection<LogicalFlow> getFlows() {
        ITEE tee = getTEE();
        return tee.getFlows();
    }

    @Path("/routes/{srcIP}/{dstIP}")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public Collection<Route> getRoutes(@PathParam("srcIP") String srcIP, @PathParam("dstIP") String dstIP) {
        ITEE tee = getTEE();
        System.out.println("NB :: "+srcIP+" to "+dstIP);
        return tee.getRoutes(srcIP, dstIP);
    }

    @Path("/move/{fromRoute}/{flow}/{toRoute}")
    @Produces(MediaType.APPLICATION_JSON)
    @PUT
    public void moveFlow(
            @PathParam("fromRoute") String fromRoute,
            @PathParam("flow") String flow,
            @PathParam("toRoute") String toRoute) {
        ITEE tee = getTEE();
        System.out.println("NB :: move flow: "+ flow +" from "+fromRoute+" to "+toRoute);
        if (tee.moveFlow(Integer.parseInt(fromRoute), Integer.parseInt(flow), Integer.parseInt(toRoute))) {
            Response.ok(); // Flow moved
        } else {
            Response.serverError(); // Flow not moved - wrong input
        }
    }

    private ITEE getTEE() {
        ITEE tee = (ITEE) ServiceHelper
                .getGlobalInstance(ITEE.class, this);
        if (tee == null) {
            /* Service not found. */
            throw new ServiceUnavailableException("TEE "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }
        return tee;
    }

}
