/*
 * Copyright 1997-2001 by Oracle and/or its affiliates.,
 * 901 San Antonio Road, Palo Alto, California, 94303, U.S.A.
 * All rights reserved.
 *
 * This software is the confidential and proprietary information
 * of Oracle and/or its affiliates. ("Confidential Information").  You
 * shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement
 * you entered into with Sun.
 */


import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
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

/**
 * This program executes the Diffie-Hellman key agreement protocol
 * between 2 parties: Alice and Bob.
 *
 * By default, preconfigured parameters (1024-bit prime modulus and base
 * generator used by SKIP) are used.
 * If this program is called with the "-gen" option, a new set of
 * parameters is created.
 */


public class Crypto {
	
	
	
	// The SKIP 1024 bit modulus
    private static final BigInteger i1024Modulus
    = giveMeBiggo();

    // The base used with the SKIP 1024 bit modulus
    private static final BigInteger i1024Base = BigInteger.valueOf(2);
    
	public static BigInteger giveMeBiggo() {
		Random rnd = new Random(System.currentTimeMillis());
		BigInteger biggo = BigInteger.probablePrime(1024, rnd);
		return biggo;
	}
	
	
	public static byte[] createKeyPairGenerator()
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
		
		 DHParameterSpec dhSkipParamSpec;

//	        if (mode.equals("GENERATE_DH_PARAMS")) {
//	            // Some central authority creates new DH parameters
//	            System.out.println
//	                ("Creating Diffie-Hellman parameters (takes VERY long) ...");
//	            AlgorithmParameterGenerator paramGen
//	                = AlgorithmParameterGenerator.getInstance("DH");
//	            paramGen.init(512);
//	            AlgorithmParameters params = paramGen.generateParameters();
//	            dhSkipParamSpec = (DHParameterSpec)params.getParameterSpec
//	                (DHParameterSpec.class);
//	        } else {
	            // use some pre-generated, default DH parameters
	            System.out.println("Using SKIP Diffie-Hellman parameters");
	            dhSkipParamSpec = new DHParameterSpec(i1024Modulus,
	                                                  i1024Base);
//	        }

	        /*
	         * Alice creates her own DH key pair, using the DH parameters from
	         * above
	         */
	        System.out.println("ALICE: Generate DH keypair ...");
	        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
	        aliceKpairGen.initialize(dhSkipParamSpec);
	        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

	        // Alice creates and initializes her DH KeyAgreement object
	        System.out.println("ALICE: Initialization ...");
	        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
	        aliceKeyAgree.init(aliceKpair.getPrivate());

	        // Alice encodes her public key, and sends it over to Bob.
	        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

	        /*
	         * Let's turn over to Bob. Bob has received Alice's public key
	         * in encoded format.
	         * He instantiates a DH public key from the encoded key material.
	         */
	        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec
	            (alicePubKeyEnc);
	        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

	        /*
	         * Bob gets the DH parameters associated with Alice's public key. 
	         * He must use the same parameters when he generates his own key
	         * pair.
	         */
	        DHParameterSpec dhParamSpec = ((DHPublicKey)alicePubKey).getParams();

	        // Bob creates his own DH key pair
	        System.out.println("BOB: Generate DH keypair ...");
	        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
	        bobKpairGen.initialize(dhParamSpec);
	        KeyPair bobKpair = bobKpairGen.generateKeyPair();

	        // Bob creates and initializes his DH KeyAgreement object
	        System.out.println("BOB: Initialization ...");
	        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
	        bobKeyAgree.init(bobKpair.getPrivate());

	        // Bob encodes his public key, and sends it over to Alice.
	        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

	        /*
	         * Alice uses Bob's public key for the first (and only) phase
	         * of her version of the DH
	         * protocol.
	         * Before she can do so, she has to instanticate a DH public key
	         * from Bob's encoded key material.
	         */
	        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
	        x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
	        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
	        System.out.println("ALICE: Execute PHASE1 ...");
	        aliceKeyAgree.doPhase(bobPubKey, true);

	        /*
	         * Bob uses Alice's public key for the first (and only) phase
	         * of his version of the DH
	         * protocol.
	         */
	        System.out.println("BOB: Execute PHASE1 ...");
	        bobKeyAgree.doPhase(alicePubKey, true);
	            
	        /*
	         * At this stage, both Alice and Bob have completed the DH key
	         * agreement protocol.
	         * Both generate the (same) shared secret.
	         */
	        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
	        int aliceLen = aliceSharedSecret.length;

	        byte[] bobSharedSecret = new byte[aliceLen];
	        int bobLen;
	        try {
	            // show example of what happens if you
	            // provide an output buffer that is too short
	            bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 1);
	        } catch (ShortBufferException e) {
	            System.out.println(e.getMessage());
	        }
	        // provide output buffer of required size
	        bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);

//	        System.out.println("Alice secret: " + 
//	          toHexString(aliceSharedSecret));
//	        System.out.println("Bob secret: " + 
//	          toHexString(bobSharedSecret));
//
//	        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
//	            throw new Exception("Shared secrets differ");
//	        System.out.println("Shared secrets are the same");

		return aliceSharedSecret;
	}
}
