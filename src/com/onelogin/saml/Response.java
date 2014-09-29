package com.onelogin.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.onelogin.AccountSettings;

import java.lang.reflect.Method;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class Response {
	
	private Document xmlDoc;
	private AccountSettings accountSettings;
	private Certificate certificate;
	
	Response() {
	}
	
	public Response(AccountSettings accountSettings) throws CertificateException {
		this.accountSettings = accountSettings;
		certificate = new Certificate();
		certificate.loadCertificate(this.accountSettings.getCertificate());
	}
	
	public void loadXml(String xml) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory fty = DocumentBuilderFactory.newInstance();
		fty.setNamespaceAware(true);
		fty.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		DocumentBuilder builder = fty.newDocumentBuilder();
		ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes());
		xmlDoc = builder.parse(bais);		
	}
	
	
	public void loadXmlFromBase64(String response) throws ParserConfigurationException, SAXException, IOException {
		Base64 base64 = new Base64();
		byte [] decodedB = base64.decode(response);		
		String decodedS = new String(decodedB);				
		loadXml(decodedS);	
	}
		
        public boolean isValid() throws Exception {
            NodeList nodes = xmlDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

            if (nodes == null || nodes.getLength() == 0) {
                throw new Exception("Can't find signature in document.");
            }

            if (setIdAttributeExists()) {
                tagIdAttributes(xmlDoc);
            }

            X509Certificate cert = certificate.getX509Cert();
            DOMValidateContext ctx = new DOMValidateContext(cert.getPublicKey(), nodes.item(0));
            XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");
            XMLSignature xmlSignature = sigF.unmarshalXMLSignature(ctx);

            return xmlSignature.validate(ctx);
        }
	
	public String getNameId() throws Exception {
		NodeList nodes = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");		

		if(nodes.getLength()==0){
			throw new Exception("No name id found in document");
		}		

		return nodes.item(0).getTextContent();
	}
	
	public String getDecryptedAssertion(String privateKey, String encryptedSymKey, String cipherText, String encMethod) throws GeneralSecurityException{
		
		//Load in the private key
		PrivateKey key = loadPrivateKey(privateKey);
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");

		//Decrypt the key
		cipher.init(Cipher.DECRYPT_MODE, key); //privKey stored earlier
		byte[] symKey = cipher.doFinal( Base64.decodeBase64( encryptedSymKey ) );
		
		//Get the cipher'd  data base64 decoded
		byte[] cipherBytes = Base64.decodeBase64(cipherText);
		
		//Get the IV value, which is the first 16 bytes of the cipherBytes
		AlgorithmParameterSpec iv = new IvParameterSpec(cipherBytes, 0, 16);
		
		//Create a secret key based on symKey
		SecretKeySpec secretSauce = new SecretKeySpec(symKey, "AES");
		
		String cipherMethod = "";
		
		//TODO: this should be a switch statement or an enum but Java 1.6 doesn't support string switches
		String[] AES_CBC_PKCS5Padding = {"http://www.w3.org/2001/04/xmlenc#aes128-cbc",
			"http://www.w3.org/2001/04/xmlenc#aes192-cbc",
			"http://www.w3.org/2001/04/xmlenc#aes256-cbc",
			"http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.cbc.pkcs5"};
		
		String[] AES_CBC_NoPadding = {"internal:AES/CBC/NoPadding"};
		
		String[] AESWrap = {"http://www.w3.org/2001/04/xmlenc#kw-aes128",
				"http://www.w3.org/2001/04/xmlenc#kw-aes256"};
		
		String[] AES_ECB_PKCS5Padding = {"http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.ecb.pkcs5"};
		
		String[] AES_ECB_NoPadding = {"http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.ecb.nopad"};
		
		if(java.util.Arrays.asList(AES_CBC_PKCS5Padding).indexOf(encMethod) >= 0 ){			
			cipherMethod = "AES/CBC/PKCS5Padding";			
		}else if(java.util.Arrays.asList(AES_CBC_NoPadding).indexOf(encMethod) >= 0){
			cipherMethod = "AES/CBC/NoPadding";	
		}else if(java.util.Arrays.asList(AESWrap).indexOf(encMethod) >= 0){
			cipherMethod = "AESWrap";	
		}else if(java.util.Arrays.asList(AES_ECB_PKCS5Padding).indexOf(encMethod) >= 0){
			cipherMethod = "AES/ECB/PKCS5Padding";	
		}else if(java.util.Arrays.asList(AES_ECB_NoPadding).indexOf(encMethod) >= 0){
			cipherMethod = "AES/ECB/NoPadding";	
		}else{
			
			//default to this for now?
			cipherMethod = "AES/CBC/PKCS5Padding";	
		}
		
		//Now we have all the ingredients to decrypt
		cipher = Cipher.getInstance( cipherMethod );
		cipher.init(Cipher.DECRYPT_MODE, secretSauce, iv);
		
		//Do the decryption
		byte[] decrypedBytes = cipher.doFinal(cipherBytes);
		
		//Strip off the the first 16 bytes because those are the IV
		return new String( decrypedBytes, 16, decrypedBytes.length-16 );
	}
	
	private static PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
	    byte[] clear = Base64.decodeBase64(key64);
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    PrivateKey priv = fact.generatePrivate(keySpec);
	    Arrays.fill(clear, (byte) 0);
	    return priv;
	}
        
    private void tagIdAttributes(Document xmlDoc) {
        NodeList nodeList = xmlDoc.getElementsByTagName("*");
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                if (node.getAttributes().getNamedItem("ID") != null) {
                    ((Element) node).setIdAttribute("ID", true);
                }
            }
        }
    }

    private boolean setIdAttributeExists() {
        for (Method method : Element.class.getDeclaredMethods()) {
            if (method.getName().equals("setIdAttribute")) {
                return true;
            }
        }
        return false;
    }

        
}
