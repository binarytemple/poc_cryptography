package net.packetops;

import java.security.Key;


public class RSAKeyImpl implements RSAKey {

	private Key key;

	public RSAKeyImpl(Key key) {
		this.key = key;
	}

	public Key getKey() {
		return key;
	}

}
