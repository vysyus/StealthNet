import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class StealthNetSecurity {

	byte[] seed = null;
	SecureRandom sprng = null;
	MessageDigest md = null;
	SecureRandom macSprng = null;
	private boolean started;
	private byte[] sharedKey;
	byte[] token = new byte[64];
	String encryptedPacket64 = null;


	public StealthNetSecurity() {
		this.started = false;
	}
	
	public void start (byte[] key) {
		this.sharedKey = key;
		try {
			// create hash of the sharedKey
			this.md = MessageDigest.getInstance("SHA-512");
			this.seed = md.digest(key);
			// seed the first PRNG that is used for E/D packets
			this.sprng = SecureRandom.getInstance("SHA1PRNG");
			this.sprng.setSeed(seed);
			
			this.macSprng = SecureRandom.getInstance("SHA1PRNG");
			this.macSprng.setSeed(seed);
			// seed the second PRNG that is used for creating MACs

			// initialize the method
			this.started = true;
			sprng.nextBytes(this.token);
			// TODO check token
			
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		}
	}
	
	public byte[] calculateMac(byte[] key) {
		Mac mac = null;
		SecretKey macSecretKey;
		KeyGenerator macKg;
		byte[] macFinal = null;
		try {
			mac = Mac.getInstance("HmacSHA512");
			macKg = KeyGenerator.getInstance("Blowfish");
			macKg.init(128, macSprng);
			macSecretKey = macKg.generateKey();
			mac.init(macSecretKey);
			macFinal = mac.doFinal(key);
			return macFinal;
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		return macFinal;
	}
	
	public boolean checkMac(byte[] bytes, byte[] mac) {
		byte[] calculatedHmac = calculateMac(bytes);
		// the MACs are good, that means that packet is in tact
		if (Arrays.equals(mac, calculatedHmac)) return true;
 		// MACs are not good...
		return false;
	}
	
	public byte[] getSessionToken() {
		return md.digest(token);
	}
	
	/**
	 * Changes the session token to a different (pseudo) random sequence of bytes
	 * 
	 * @author Jakub Krajcovic (SID: 308064097)
	 * @author jakub@student.usyd.edu.au
	 */
	public void changeToken() {
		this.sprng.nextBytes(token);
	}
	
	public String encrypt(StealthNetPacket pckt) {
	
		byte[] mac = null;
		byte[] ciphertext = null;
		byte[] encryptedPacket = null;
		
		SecretKey cipherSecretKey;

		Cipher clientCipher;
		KeyGenerator clientKg;


		try {
			IvParameterSpec ivSpec = new IvParameterSpec(seed, 0, 8);
			clientKg = KeyGenerator.getInstance("Blowfish");
			clientKg.init(128, sprng);
			cipherSecretKey = clientKg.generateKey();
			clientCipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
			clientCipher.init(Cipher.ENCRYPT_MODE, cipherSecretKey, ivSpec,
					sprng);
			ciphertext =  clientCipher.doFinal(pckt.getBytes());
			mac = calculateMac(ciphertext);
			encryptedPacket = new byte[mac.length + ciphertext.length];
			System.arraycopy(ciphertext, 0, encryptedPacket, 0,
					ciphertext.length);
			System.arraycopy(mac, 0, encryptedPacket, ciphertext.length,
					mac.length);
			
			encryptedPacket64 = Base64.encodeBytes(encryptedPacket, Base64.DONT_BREAK_LINES);

		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		return encryptedPacket64;
			
	}
	
	public StealthNetPacket decrypt(String encodedPacket64) {
		StealthNetPacket packet = null;
		byte[] encryptedPacket = Base64.decode(encodedPacket64);
		byte[] plaintext = null;
		byte[] ciphertext = new byte[encryptedPacket.length-64];
		byte[] mac = new byte[64]; 
		SecretKey cipherSecretKey;
		KeyGenerator clientKg;
		
		
		// copy stuff into "ciphertext"
		System.arraycopy(encryptedPacket, 0, ciphertext, 0, ciphertext.length);
		// cope stuff into "mac"
		System.arraycopy(encryptedPacket, ciphertext.length, mac, 0, 64);
		if (!checkMac(ciphertext, mac)) {
			System.err.println("MACs do not match, discarding packet");
			return new StealthNetPacket(StealthNetPacket.CMD_NULL, null);
		}
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(seed, 0, 8);
			clientKg = KeyGenerator.getInstance("Blowfish");
			clientKg.init(128, sprng);
			cipherSecretKey = clientKg.generateKey();
			Cipher clientCipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
			clientCipher.init(Cipher.DECRYPT_MODE, cipherSecretKey, ivSpec, sprng);
			plaintext = clientCipher.doFinal(ciphertext);
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		
		packet = new StealthNetPacket(plaintext);
		return packet;
		
	}
}