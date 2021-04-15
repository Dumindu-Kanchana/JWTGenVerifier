package org.wso2.jwt.verifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import static org.wso2.jwt.verifier.JWTVerifier.getCertificate;

public class JWTGenerator {

    public static void main(String[] args) {

        Certificate certificate = getCertificate("src/main/resources/keystore.jks","wso2carbon");
        String jwtHeader = buildHeader(certificate);
        String jwtBody = buildBody();

        String base64UrlEncodedHeader = encode(jwtHeader.getBytes(Charset.defaultCharset()));
        String base64UrlEncodedBody = encode(jwtBody.getBytes());
        String assertion = base64UrlEncodedHeader + '.' + base64UrlEncodedBody;
        byte[] signedAssertion = signJwt(assertion,(PrivateKey) getPrivateKey("src/main/resources/keystore.jks",
                "wso2carbon"),"SHA256withRSA");
        String base64UrlEncodedAssertion = encode(signedAssertion);

        System.out.println("JWT is = " + base64UrlEncodedHeader + '.' + base64UrlEncodedBody + '.' + base64UrlEncodedAssertion);

    }

    private static String buildHeader( Certificate publicCert) {
        StringBuilder jwtHeader = new StringBuilder();
        try {
            //generate the SHA-1 thumbprint of the certificate
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = publicCert.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();
            String publicCertThumbprint = hexify(digestInBytes);
            String base64UrlEncodedThumbPrint;
            base64UrlEncodedThumbPrint = java.util.Base64.getUrlEncoder()
                    .encodeToString(publicCertThumbprint.getBytes("UTF-8"));
            //Sample header
            //{"typ":"JWT", "alg":"SHA256withRSA", "x5t":"a_jhNus21KVuoFx65LmkW2O_l10"}
            //{"typ":"JWT", "alg":"[2]", "x5t":"[1]"}
            jwtHeader.append("{\"typ\":\"JWT\",");
            jwtHeader.append("\"alg\":\"");
            jwtHeader.append("RS256");
            jwtHeader.append("\",");

            jwtHeader.append("\"x5t\":\"");
            jwtHeader.append(base64UrlEncodedThumbPrint);
            jwtHeader.append('\"');

            jwtHeader.append('}');

        } catch (Exception e) {

        }
        return jwtHeader.toString();

    }

    public static String hexify(byte bytes[]) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }

    public static String buildBody() {

        Map<String, String> standardClaims = populateStandardClaims();
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();

        if(standardClaims != null) {
            Iterator<String> it = new TreeSet(standardClaims.keySet()).iterator();
            while (it.hasNext()) {
                String claimURI = it.next();
                String claimVal = standardClaims.get(claimURI);
                List<String> claimList = new ArrayList<String>();
                if (claimVal != null && claimVal.contains("{")) {
                    ObjectMapper mapper = new ObjectMapper();
                    try {
                        Map<String, String> map = mapper.readValue(claimVal, Map.class);
                        jwtClaimsSetBuilder.claim(claimURI, map);
                    } catch (IOException e) {
                        // Exception isn't thrown in order to generate jwt without claim, even if an error is
                        // occurred during the retrieving claims.
                        System.out.println("Error while reading claim values for " + claimVal + " " + e);
                    }
                } else if ( claimVal != null && claimVal.contains(",")) {
                    StringTokenizer st = new StringTokenizer(claimVal, ",");
                    while (st.hasMoreElements()) {
                        String attValue = st.nextElement().toString();
                        if (StringUtils.isNotBlank(attValue)) {
                            claimList.add(attValue);
                        }
                    }
                    jwtClaimsSetBuilder.claim(claimURI, claimList);
                } else if ("exp".equals(claimURI)) {
                    jwtClaimsSetBuilder.expirationTime(new Date(Long.valueOf(standardClaims.get(claimURI))));
                } else {
                    jwtClaimsSetBuilder.claim(claimURI, claimVal);
                }
            }
        }

        return jwtClaimsSetBuilder.build().toJSONObject().toJSONString();
    }

    public static Map<String, String> populateStandardClaims() {

        //generating expiring timestamp
        long currentTime = System.currentTimeMillis();
        long expireIn = currentTime + 3600 * 1000;

        String dialect = "http://org.wso2.carbon/wso2/caims";

        String subscriber = "setSubscriber";
        String applicationName = "test_role_app_2,app2";
        String applicationId = "1253";
        String endUserName = "testGDK";
        String uuid = "dafa-fafa-fefw-gege-test";

        Map<String, String> claims = new LinkedHashMap<String, String>(20);

        claims.put("iss", "IDP_JWT_ISSUER");
        claims.put("sub","duminduk");
        claims.put("aud", "wso2_keymanager");
        claims.put("exp", String.valueOf(expireIn));
        claims.put(dialect + "/subscriber", subscriber);
        claims.put(dialect + "/applicationid", applicationId);
        claims.put(dialect + "/applicationname", applicationName);
        claims.put(dialect + "/apicontext", "/test/api");
        claims.put(dialect + "/version", "v1");
        claims.put(dialect + "/enduser", endUserName);
        claims.put(dialect + "/applicationUUId", uuid);

        return claims;
    }

    public static byte[] signJwt(String assertion, PrivateKey privateKey, String signatureAlgorithm) {
        try {
            //initialize signature with private key and algorithm
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);

            //update signature with data to be signed
            byte[] dataInBytes = assertion.getBytes(Charset.defaultCharset());
            signature.update(dataInBytes);

            //sign the assertion and return the signature
            return signature.sign();
        } catch (Exception e) {
            System.out.println("error occured " + e);
        }
        return null;
    }

    public static String encode(byte[] stringToBeEncoded){
        return java.util.Base64.getUrlEncoder().encodeToString(stringToBeEncoded);
    }

    public static Key getPrivateKey(String keystoreLocation, String keystorePassword) {
        Key privateKey;

        try (FileInputStream trustStoreStream = new FileInputStream(new File(keystoreLocation))) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(trustStoreStream, keystorePassword.toCharArray());
            privateKey = keystore.getKey("wso2carbon",keystorePassword.toCharArray());
            return privateKey;
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.out.println("Error in loading trust store." + e);
        }
        return null;
    }
}
