package com.onelogin;

public class AppSettings {
	private String assertionConsumerServiceUrl;
	private String issuer;
	private String namedIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
	
	public String getAssertionConsumerServiceUrl() {
		return assertionConsumerServiceUrl;
	}
	public void setAssertionConsumerServiceUrl(String assertionConsumerServiceUrl) {
		this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
	}
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public String getNamedIdFormat() {
		return namedIdFormat;
	}
	public void setNamedIdFormat(String namedIdFormat) {
		this.namedIdFormat = namedIdFormat;
	}

}
