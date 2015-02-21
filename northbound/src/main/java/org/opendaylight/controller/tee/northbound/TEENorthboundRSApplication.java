package org.opendaylight.controller.tee.northbound;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

public class TEENorthboundRSApplication extends Application {
    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<Class<?>>();
        classes.add(TEENorthbound.class);
        return classes;
    }
}
