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
 * REVISION HISTORY:
 *
 **********************************************************************************/

/* Import Libraries **********************************************************/

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
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
    
	public static BigInteger giveMeBiggo(int length ) {
		Random rnd = new Random(System.currentTimeMillis());
		BigInteger biggo = BigInteger.probablePrime(length, rnd);
		return biggo;
	}
	
    public StealthNetComms() {
        commsSocket = null;
        dataIn = null;
        dataOut = null;
    }

    protected void finalize() throws IOException {
        if (dataOut != null)
            dataOut.close();
        if (dataIn != null)
            dataIn.close();
        if (commsSocket != null)
            commsSocket.close();
    }
//    private void createServerKey() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException{
//    	{
//    		/*
//             * Let's turn over to Server. Server has received Client's public key
//             * in encoded format.
//             * He instantiates a DH public key from the encoded key material.
//             */
//            KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
//            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec
//                (clientPubKeyEnc);
//            PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);
//
//            /*
//             * Server gets the DH parameters associated with Client's public key. 
//             * He must use the same parameters when he generates his own key
//             * pair.
//             */
//
//            
//            DHParameterSpec dhParamSpec = ((DHPublicKey)clientPubKey).getParams();
//
//            // Server creates his own DH key pair
//            System.out.println("SERVER: Generate DH keypair ...");
//            KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
//            serverKpairGen.initialize(dhParamSpec);
//            KeyPair serverKpair = serverKpairGen.generateKeyPair();
//
//            // Server creates and initializes his DH KeyAgreement object
//            System.out.println("SERVER: Initialization ...");
//            KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
//            serverKeyAgree.init(serverKpair.getPrivate());
//
//            // Server encodes his public key, and sends it over to Client.
//            byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
//
//            /*
//             * Client uses Server's public key for the first (and only) phase
//             * of her version of the DH
//             * protocol.
//             * Before she can do so, she has to instanticate a DH public key
//             * from Server's encoded key material.
//             */
//            KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
//            x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
//            PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
//            System.out.println("CLIENT: Execute PHASE1 ...");
//            clientKeyAgree.doPhase(serverPubKey, true);
//
//            /*
//             * Server uses Client's public key for the first (and only) phase
//             * of his version of the DH
//             * protocol.
//             */
//            System.out.println("SERVER: Execute PHASE1 ...");
//            serverKeyAgree.doPhase(clientPubKey, true);
//                
//            /*
//             * At this stage, both Client and Server have completed the DH key
//             * agreement protocol.
//             * Both generate the (same) shared secret.
//             */
//            byte[] clientSharedSecret = clientKeyAgree.generateSecret();
//            int clientLen = clientSharedSecret.length;
//
//            byte[] serverSharedSecret = new byte[clientLen];
//    	}
    
    private void createClientKey() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException{
    	dhParams = new DHParameterSpec(giveMeBiggo(1024),
    			giveMeBiggo(7)); 
    	/*
         * Client creates her own DH key pair, using the DH parameters from
         * above
         */
        System.out.println("CLIENT: Generate DH keypair ...");
        KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
        clientKpairGen.initialize(dhParams);
        KeyPair clientKpair = clientKpairGen.generateKeyPair();

        // Client creates and initializes her DH KeyAgreement object
        System.out.println("CLIENT: Initialization ...");
        clientKeyAgree = KeyAgreement.getInstance("DH");
        clientKeyAgree.init(clientKpair.getPrivate());

        // Client encodes her public key, and sends it over to Server.
        byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();

    }
    
    
    public boolean initiateSession(Socket socket) {
        try {
        	
        	dhParams = new DHParameterSpec(giveMeBiggo(1024),
        			giveMeBiggo(7)); 
        	/*
             * Client creates her own DH key pair, using the DH parameters from
             * above
             */
            System.out.println("CLIENT: Generate DH keypair ...");
            KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
            clientKpairGen.initialize(dhParams);
            KeyPair clientKpair = clientKpairGen.generateKeyPair();
                        
            System.out.println("This is the private client key: "+ clientKpair.getPrivate()+ " and this the public: " + clientKpair.getPublic());

            // Client creates and initializes her DH KeyAgreement object
            System.out.println("CLIENT: Initialization ...");
            setClientKeyAgree(KeyAgreement.getInstance("DH"));
            getClientKeyAgree().init(clientKpair.getPrivate());

            // Client encodes her public key, and sends it over to Server.
            byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
            System.out.println("This is the encoded alice key: "+ clientPubKeyEnc);

        	commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(
                commsSocket.getInputStream()));
            sendPacket(StealthNetPacket.CMD_KEYINIT, clientPubKeyEnc);
            
            
            
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
        pckt.command = command;
        pckt.data = new byte[size];
        System.arraycopy(data, 0, pckt.data, 0, size);
        return sendPacket(pckt);
    }

    public boolean sendPacket(StealthNetPacket pckt) {
        if (dataOut == null)
            return false;
        dataOut.println(pckt.toString());
        return true;
    }

    public StealthNetPacket recvPacket() throws IOException {
        StealthNetPacket pckt = null;
        String str = dataIn.readLine();
        pckt = new StealthNetPacket(str);
        return pckt;
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

	public void setClientKeyAgree(KeyAgreement clientKeyAgree) {
		this.clientKeyAgree = clientKeyAgree;
	}

	public KeyAgreement getClientKeyAgree() {
		return clientKeyAgree;
	}
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/
 
