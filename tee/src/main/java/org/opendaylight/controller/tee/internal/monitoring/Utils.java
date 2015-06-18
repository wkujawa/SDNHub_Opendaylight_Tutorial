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

import java.text.DecimalFormat;

public class Utils {
    public final static long BASE = 1024; // TODO is that base in OpenFlow, etc.
    public final static long KB = BASE,
            MB = KB * BASE,
            GB = MB * BASE,
            TB = GB * BASE;
    private final static long[] mSize = { TB, GB, MB, KB, };
    private final static String[] mUnit = { "Tb", "Gb", "Mb", "Kb", };

    private final static DecimalFormat df = new DecimalFormat("#.##");

    public static String printWithUnit(long bytes) {
        for (int i = 0; i < mSize.length; ++i) {
            if (bytes >= mSize[i]) {
                return df.format(bytes / mSize[i]) + " " + mUnit[i] + "/s";
            }
        }
        return df.format(bytes) + " b/s";
    }

    public static String mac2str(long mac) {
        StringBuilder sb = new StringBuilder(":::::");
        byte b;
        for (int i = 0; i < 6; i++) {
            b = (byte) (mac % 256);
            mac /= 256;
            sb.insert(5-i, String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String mac2str(byte[] mac) {
        StringBuilder sb = new StringBuilder(18);
        for (byte b : mac) {
            if (sb.length() > 0)
                sb.append(':');
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
