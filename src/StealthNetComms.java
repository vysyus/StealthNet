/***********************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetComms.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Communications for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0
 * IMPLEMENTS:      initiateSession();
 *                  acceptSession();
 *                  terminateSession();
 *                  sendPacket();
 *                  recvPacket();
 *                  recvReady();
 *
 * REVISION HISTORY:Modified by Juraj Martinak (SID 309128722) and Marius
 * 					KrŠmer (SID xxx) to incorporate cryptography for
 * 					ELEC 5616 programming assignment.
 *
 **********************************************************************************/

/* Import Libraries **********************************************************/

import java.math.BigInteger;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.io.*;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/* StealthNetComms class *****************************************************/

public class StealthNetComms {
    public static final String SERVERNAME = "localhost";
    public static final int SERVERPORT = 5616;

    private Socket commsSocket;             // communications socket
    private PrintWriter dataOut;            // output data stream
    private BufferedReader dataIn;          // input data stream
    private DHParameterSpec dhParams;
    private KeyAgreement clientKeyAgree;
	private byte[] clientSharedKey;
	private StealthNetSecurity secure;
	private boolean SECURE;
	private byte[] sessionToken;
	
    private void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
	
	private String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        } 
        return buf.toString();
    }

    public StealthNetComms() {
        commsSocket = null;
        dataIn = null;
        dataOut = null;
        sessionToken = null;
        secure = new StealthNetSecurity();
        SECURE = false;
    }
    


    protected void finalize() throws IOException {
        if (dataOut != null)
            dataOut.close();
        if (dataIn != null)
            dataIn.close();
        if (commsSocket != null)
            commsSocket.close();
    }
    
	public static BigInteger giveMeBiggo(int length ) {
		Random rnd = new Random(System.currentTimeMillis());
		BigInteger biggo = BigInteger.probablePrime(length, rnd);
		return biggo;
	}

    public boolean initiateSession(Socket socket) {
        try {
        	
        	dhParams = new DHParameterSpec(giveMeBiggo(1024),
        			giveMeBiggo(7)); 
        	/*
             * Client creates her own DH key pair, using the DH parameters from
             * above
             */
            KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
            clientKpairGen.initialize(dhParams);
            KeyPair clientKpair = clientKpairGen.generateKeyPair();

            // Client creates and initializes her DH KeyAgreement object
            clientKeyAgree = KeyAgreement.getInstance("DH");
            clientKeyAgree.init(clientKpair.getPrivate());

            // Client encodes her public key, and sends it over to Server.
            byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
        	
        	commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(
                commsSocket.getInputStream()));
            
            sendPacket(StealthNetPacket.CMD_KEYEX, clientPubKeyEnc);
            
            StealthNetPacket pckt = recvPacket();
			byte[] serverPubKeyEncoded = pckt.data;

			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEncoded);
			PublicKey serverPubKey = keyFactory.generatePublic(x509KeySpec);
			
			// now let's do the first phase of the agree
			clientKeyAgree.doPhase(serverPubKey, true);
			clientSharedKey = clientKeyAgree.generateSecret();

			//System.out.println("Shared key calculated by client: " + toHexString (clientSharedKey));
			secure.start(clientSharedKey);
			sessionToken = secure.getSessionToken();
			// TODO token check
            
        } catch (Exception e) {
            System.err.println("Connection terminated.");
            System.exit(1);
        }

        return true;
    }

    public boolean acceptSession(Socket socket) {
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(
                commsSocket.getInputStream()));
            
            StealthNetPacket pckt = recvPacket();
            byte[] clientPubKeyEnc = pckt.data;
			/*
             * Let's turn over to Server. Server has received Client's public key
             * in encoded format.
             * He instantiates a DH public key from the encoded key material.
             */
            KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec
                (clientPubKeyEnc);
            PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);
            
			
			/*
             * Server gets the DH parameters associated with Client's public key. 
             * He must use the same parameters when he generates his own key
             * pair.
             */

            
            DHParameterSpec dhParamSpec = ((DHPublicKey)clientPubKey).getParams();

            // Server creates his own DH key pair
            KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
            serverKpairGen.initialize(dhParamSpec);
            KeyPair serverKpair = serverKpairGen.generateKeyPair();

            // Server creates and initializes his DH KeyAgreement object
            KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
            serverKeyAgree.init(serverKpair.getPrivate());

            // Server encodes his public key, and sends it over to Client.
            byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
            sendPacket(StealthNetPacket.CMD_KEYEX, serverPubKeyEnc);

            serverKeyAgree.doPhase(clientPubKey, true);
            byte[] serverSharedKey = serverKeyAgree.generateSecret();
            
         //   System.out.println("Shared key calculated by server: " + toHexString(serverSharedKey));


            secure.start(serverSharedKey);
			sessionToken = secure.getSessionToken();

            //TODO check token
        } catch (Exception e) {
            System.err.println("Connection terminated.");
            System.exit(1);
        }

        return true;
    }

    public boolean terminateSession() {
        try {
            if (commsSocket == null)
                return false;
            dataIn.close();
            dataOut.close();
            commsSocket.close();
            commsSocket = null;
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public boolean sendPacket(byte command) {
        return sendPacket(command, new byte[0]);
    }

    public boolean sendPacket(byte command, String data) {
        System.out.println("String data: " + data);
        return sendPacket(command, data.getBytes());
    }

    public boolean sendPacket(byte command, byte[] data) {
        return sendPacket(command, data, data.length);
    }

    public boolean sendPacket(byte command, byte[] data, int size) {
    	StealthNetPacket pckt = new StealthNetPacket();
		if (SECURE == true ) {
			sessionToken = secure.getSessionToken();
			byte[] newData = new byte[size+sessionToken.length];
			System.arraycopy(data, 0, newData, 0, size);
			System.arraycopy(sessionToken, 0, newData, size, sessionToken.length);
			pckt.command = command;
			pckt.data = new byte[newData.length];
			System.arraycopy(newData, 0, pckt.data, 0, newData.length);
			return sendPacket(pckt);
		} else {
			pckt.command = command;
			pckt.data = new byte[size];
			System.arraycopy(data, 0, pckt.data, 0, size);
		}
		return sendPacket(pckt);
    }

    public boolean sendPacket(StealthNetPacket pckt) {
		if (dataOut == null)
			return false;
		if (SECURE == true) {
			String encryptedPacketString = secure.encrypt(pckt);
			dataOut.println(encryptedPacketString);
			secure.changeToken();
			return true;
		}
		dataOut.println(pckt.toString());
		return true;
    }

    public StealthNetPacket recvPacket() throws IOException {
    	StealthNetPacket packet = null;
		String str = dataIn.readLine();
		
		if (SECURE == true) {
			packet = secure.decrypt(str);
			
			if (packet.command == StealthNetPacket.CMD_CHECKSUM) {
				System.err.println("MAC checksum failed");
				return new StealthNetPacket(StealthNetPacket.CMD_CHECKSUM, null);
			}
			
			byte[] tmpSessionKey = secure.getSessionToken();
			byte[] receivedSessionToken = new byte[tmpSessionKey.length];
			byte[] actualData = new byte[packet.data.length-receivedSessionToken.length];
			System.arraycopy(packet.data, 0, actualData, 0, packet.data.length-tmpSessionKey.length);
			System.arraycopy(packet.data, packet.data.length-tmpSessionKey.length, receivedSessionToken, 0, tmpSessionKey.length);
			if (Arrays.equals(receivedSessionToken, tmpSessionKey)) {
				// Session token is valid
				packet.data = actualData;
				secure.changeToken();
				return packet;
			} else {
				System.err.println("Invalid session token");
				// Session token is invalid, return a CMD_XTOKEN packet
				packet.command = StealthNetPacket.CMD_TOKEN;
				packet.data = null;
				return packet;
			}
		}
		packet = new StealthNetPacket(str);
		return packet;
    }

    public boolean recvReady() throws IOException {
/*
        System.out.println("Connected: " + commsSocket.isConnected());
        System.out.println("Closed: " + commsSocket.isClosed());
        System.out.println("InClosed: " + commsSocket.isInputShutdown());
        System.out.println("OutClosed: " + commsSocket.isOutputShutdown());
*/
        return dataIn.ready();
    }
    
    public void setSecurity (boolean secure) {
    	SECURE = secure;
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/
 
