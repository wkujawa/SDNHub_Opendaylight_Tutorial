package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.text.DecimalFormat;

public class Utils {
	public final static long BASE = 1024; // TODO is that base in OpenFlow, etc.
	public final static long KB = BASE, MB = KB*BASE, GB = MB*BASE;
	private final static long [] mSize = {
		GB,
		MB,
		KB,
	};
	private final static String [] mUnit = {
		"Gb",
		"Mb",
		"Kb",
	};

	private final static DecimalFormat df = new DecimalFormat("#.##");
	
	public static String printWithUnit(long bytes) {
		for (int i=0; i<mSize.length; ++i) {
			if (bytes >= mSize[i]) {
				return df.format(bytes / mSize[i]) +" "+mUnit[i]+"/s";
			}
		}
		return df.format(bytes) +" b/s";
	}
}
