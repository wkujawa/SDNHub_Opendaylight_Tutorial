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
