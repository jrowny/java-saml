package com.onelogin.saml;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;

public class Certificate {

	private X509Certificate x509Cert;
	
	/**
	 * Loads certificate from a base64 encoded string 
	 */
 	public void loadCertificate(String certificate) throws CertificateException {
		CertificateFactory fty = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(certificate.getBytes()));
		x509Cert = (X509Certificate)fty.generateCertificate(bais);
	}
	
	/**
	 * Loads a certificate from a encoded base64 byte array.
	 * @param certificate an encoded base64 byte array.
	 * @throws CertificateException In case it can't load the certificate.
	 */
	public void loadCertificate(byte[] certificate) throws CertificateException {
		CertificateFactory fty = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(certificate));
		x509Cert = (X509Certificate)fty.generateCertificate(bais);
	}

	public X509Certificate getX509Cert() {
		return x509Cert;
	}		
	
	public static PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
	    byte[] clear = Base64.decodeBase64(key64);
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    PrivateKey priv = fact.generatePrivate(keySpec);
	    Arrays.fill(clear, (byte) 0);
	    return priv;
	}
}
