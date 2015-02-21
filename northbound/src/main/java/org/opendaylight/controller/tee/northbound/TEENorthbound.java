package org.opendaylight.controller.tee.northbound;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("/")
public class TEENorthbound {
    /**
     * Get detected hosts
     * 
     * @return - list of hosts
     */
    @Path("/hosts")
    @GET
    public Response getHosts() {
//        TutorialL2Forwarding tee = (TutorialL2Forwarding) ServiceHelper
//                .getGlobalInstance(TutorialL2Forwarding.class, this);
//        if (tee == null) {
//            /* Service not found. */
//            return Response.ok(new String("No TEE service")).status(500)
//                    .build();
//        }
//        
//        return Response.ok(tee.getAllHosts().toString()).build();
    	return Response.ok(new String("Hello from TEE nb :)")).build();
    }
}
