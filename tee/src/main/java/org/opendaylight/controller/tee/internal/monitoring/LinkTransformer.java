package org.opendaylight.controller.tee.internal.monitoring;

import org.apache.commons.collections15.Transformer;

/**
 * Transformer that extracts available link bandwidth.
 * @author Wiktor Kujawa
 */
public class LinkTransformer implements Transformer<Link, Long> {
    @Override
    public Long transform(Link arg0) {
        long x = Math.round((double) arg0.getUsage()/ arg0.getBandwidth() *100);
        return 1 + x * x;
    }
}
