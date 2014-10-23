java-saml
=========

Originally forked from One Login's Java SAML but this adds support for:

 * Logout Requests (SLO)
 * RelayState for auth requests (not yet for logout requests)
 * Signed AuthRequests as well as Logout Requests
 * Decrypting SAML responses via `getDecryptedAssertion` function
 * Added a test, I'll add more eventually
 * Refactored to simplify usage a bit, you just pass in your values and it gives you back full encoded URLs which you can just redirect to
 

With this feature set you can pretty easily achieve SAML as an SP for ADFS, PingFederate, PingOne, OneLogin, and Okta.
