package org.wso2.jwt.verifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class JWTVerifier {

    public static void main(String[] args) {

        String[] splitToken = {"",
                "",
        ""};
        Certificate certificate = getCertificate("src/main/resources/client-truststore.jks","wso2carbon");
        String signatureAlgorithm = "SHA256withRSA";
        if (verifyTokenSignature(splitToken,certificate,signatureAlgorithm)){
            System.out.println("Signature verification successful");
        } else {
            System.out.println("Signature verification failed!");
        }
    }

    public static boolean verifyTokenSignature(String[] splitToken, Certificate certificate,
                                               String signatureAlgorithm) {
        // Retrieve public key from the certificate
        PublicKey publicKey = certificate.getPublicKey();
        try {
            // Verify token signature
            Signature signatureInstance = Signature.getInstance(signatureAlgorithm);
            signatureInstance.initVerify(publicKey);
            String assertion = splitToken[0] + "." + splitToken[1];
            signatureInstance.update(assertion.getBytes());
            byte[] decodedSignature = java.util.Base64.getUrlDecoder().decode(splitToken[2]);
            return signatureInstance.verify(decodedSignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IllegalArgumentException e) {
            String msg = "Error while verifying JWT signature with signature algorithm " + signatureAlgorithm;
            System.out.println(msg + " " + e);
        }
        return false;
    }

    public static Certificate getCertificate(String trustStoreLocation, String trustStorePassword) {
        Certificate publicCert;

        try (FileInputStream trustStoreStream = new FileInputStream(new File(trustStoreLocation))) {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(trustStoreStream, trustStorePassword.toCharArray());
            publicCert = trustStore.getCertificate("wso2carbon");
            return publicCert;
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            System.out.println("Error in loading trust store." + e);
        }
        return null;
    }
}
