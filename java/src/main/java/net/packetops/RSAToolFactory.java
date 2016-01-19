package net.packetops;

import java.security.Security;



public class RSAToolFactory {

	private static RSATool instance = null;
	
	public static RSATool getRSATool() {
		if(instance == null) {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());			
			instance = new RSAToolImpl();
		}
		return instance;
	}

}
