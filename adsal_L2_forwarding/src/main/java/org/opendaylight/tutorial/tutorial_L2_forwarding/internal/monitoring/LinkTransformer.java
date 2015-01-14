package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import org.apache.commons.collections15.Transformer;

/**
 * Transformer that extracts available link bandwidth.
 * @author v1t3x
 */
public class LinkTransformer implements Transformer<Link, Long> {

    @Override
    public Long transform(Link arg0) {
        // TODO Auto-generated method stub
        return 1 + (arg0.getUsage()/ arg0.getBandwidth()*100) * (arg0.getUsage()/ arg0.getBandwidth()*100);
    }

}
