package com.onelogin.saml;

import static org.junit.Assert.*;

import java.security.GeneralSecurityException;

import org.junit.Test;

public class ResponseTest {

	@Test
	public void testGetDecryptedAssertion() throws GeneralSecurityException {
		Response test = new Response();
		String privateKey = "";
		String encryptedSymKey = "";
		String cipherText = "";
		
		String decryptedAssertion = test.getDecryptedAssertion(privateKey, encryptedSymKey, cipherText, "");

		System.out.println( decryptedAssertion );
		
		assertEquals("<Assertion", decryptedAssertion.substring(0, "<Assertion".length()));
		
	}

}
