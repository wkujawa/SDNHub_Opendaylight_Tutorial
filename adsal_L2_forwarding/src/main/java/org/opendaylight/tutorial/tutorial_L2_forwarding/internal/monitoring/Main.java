package org.opendaylight.tutorial.tutorial_L2_forwarding.internal.monitoring;

import java.io.IOException;


public class Main {
	public static void main(String[] args) {
		new NetworkMonitor();
		try {
			System.in.read();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
