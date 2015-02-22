package org.opendaylight.controller.tee.northbound;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.northbound.commons.RestMessages;
import org.opendaylight.controller.northbound.commons.exception.ServiceUnavailableException;
import org.opendaylight.controller.sal.utils.ServiceHelper;
import org.opendaylight.tutorial.tutorial_L2_forwarding.internal.ITEE;

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
