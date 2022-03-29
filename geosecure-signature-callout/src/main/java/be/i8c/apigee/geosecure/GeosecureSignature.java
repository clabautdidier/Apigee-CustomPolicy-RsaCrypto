package be.i8c.apigee.geosecure;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class GeosecureSignature implements Execution {

    public static final String PROPERTYNAME_PAYLOAD = "payload";
    public static final String PROPERTYNAME_PRIVATEKEY = "private-key";
    public static final String PROPERTYNAME_SIGNATURE = "signature";
    private final Map properties;

    public GeosecureSignature(Map properties) {
        this.properties = properties;
    }

    @Override
    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        String payload = messageContext.getVariable(PROPERTYNAME_PAYLOAD);
        String privateKey = messageContext.getVariable(PROPERTYNAME_PRIVATEKEY);
        try {
            String signature = sign(payload, privateKey);

            messageContext.setVariable(PROPERTYNAME_SIGNATURE, signature);

        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | InvalidKeySpecException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();

            return ExecutionResult.ABORT;
        }

        return ExecutionResult.SUCCESS;
    }

    byte[] stripPKCS8Headers(byte[] inbuffer) throws UnsupportedEncodingException {
        String temp = new String(inbuffer);
        String keyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
        keyPEM = keyPEM.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "");
        keyPEM = keyPEM.replace("-----END ENCRYPTED PRIVATE KEY-----", "");
        keyPEM = keyPEM.replace("-----END PRIVATE KEY-----", "");
        keyPEM = keyPEM.replace("-----END PRIVATE KEY-----", "");
        keyPEM = keyPEM.replace("-----BEGIN PUBLIC KEY-----", "");
        keyPEM = keyPEM.replace("-----END PUBLIC KEY-----", "");
        keyPEM = keyPEM.replace("-----BEGIN CERTIFICATE-----", "");
        keyPEM = keyPEM.replace("-----END CERTIFICATE-----", "");
        keyPEM = keyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        keyPEM = keyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        keyPEM = keyPEM.replace("\r", "");
        keyPEM = keyPEM.replace("\n", "");

        return Base64.getDecoder().decode(keyPEM.getBytes("UTF-8"));
    }

    PrivateKey loadPrivateKey(byte[] keyInPEM, char[] password) throws InvalidKeySpecException, IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        PKCS8EncodedKeySpec keySpec;
        KeyFactory kf = KeyFactory.getInstance("RSA");

        if (password == null || password.length == 0) {
            keySpec = new PKCS8EncodedKeySpec(stripPKCS8Headers(keyInPEM));
        } else {
            EncryptedPrivateKeyInfo pkInfo = new EncryptedPrivateKeyInfo(stripPKCS8Headers(keyInPEM));
            PBEKeySpec pbeSpec = new PBEKeySpec(password);

            SecretKeyFactory secretKFac = SecretKeyFactory.getInstance(pkInfo.getAlgName());

            Cipher cipher = Cipher.getInstance(pkInfo.getAlgName());
            cipher.init(Cipher.DECRYPT_MODE, secretKFac.generateSecret(pbeSpec), pkInfo.getAlgParameters());

            keySpec = pkInfo.getKeySpec(cipher);
        }

        return kf.generatePrivate(keySpec);
    }

    PublicKey loadPublicKey(byte[] pubBytes)
            throws Exception {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(stripPKCS8Headers(pubBytes));
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            return pubKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error loading public key", e);
        }

    }

    String signBase64(PrivateKey privkey, String payload) {
        try {
            Signature privateSignature = Signature.getInstance("Sha1withRSA");
            privateSignature.initSign(privkey);
            privateSignature.update(payload.getBytes(StandardCharsets.UTF_16LE));
            byte[] signature = privateSignature.sign();
            String signatureBase64 = Base64.getUrlEncoder().encodeToString(signature);
            return signatureBase64;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Error signing token", e);
        }
    }

    boolean verifyBase64(PublicKey pubkey, String signature, String payload) {
        try {
            byte[] signBytes = Base64.getUrlDecoder().decode(signature);
            Signature publicSignature = Signature.getInstance("Sha1withRSA");
            publicSignature.initVerify(pubkey);
            publicSignature.update(payload.getBytes(StandardCharsets.UTF_16LE));
            return (publicSignature.verify(signBytes));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Error verifying token", e);
        }
    }

    static String readAllBytesJava(String filePath) {
        String content = "";

        try {
            content = new String(Files.readAllBytes(Paths.get(filePath)));
        } catch (IOException e) {
            throw new IllegalStateException("Error reading file " + filePath);
        }

        return content;
    }

    public static void main(String args[]) {
        try {
            int argc = args.length;
            if (argc < 2) {
                System.err.println("Usage: geosecure payload key (pubkey)");
                System.exit(1);
            }

            if (args[0] != null && !new File(args[0]).exists()) {
                System.err.println("Payload file not found");
                System.exit(1);
            }
            String payload = readAllBytesJava(args[0]);

            if (args[1] != null && !new File(args[1]).exists()) {
                System.err.println("Key file not found");
                System.exit(1);
            }
            String keyfile = readAllBytesJava(args[1]);

            GeosecureSignature geosecureSignature = new GeosecureSignature(null);
            System.out.println(geosecureSignature.sign(payload, keyfile));

            if (2 < argc) {
                if (args[2] != null && !new File(args[2]).exists()) {
                    System.err.println("Public key file not found");
                    System.exit(1);
                }
                String pubkeyfile = readAllBytesJava(args[2]);

                if (geosecureSignature.verifySignature(payload, pubkeyfile, keyfile)) {
                    System.err.println("Signature OK");
                } else {
                    System.err.println("Signature NOT OK");
                }
            }

        } catch (Exception e) {
            System.err.println("Error!! " + e.getMessage());
        }
    }

    private boolean verifySignature(String payload, String pubkeyfile, String keyfile) throws Exception {
        PublicKey pubKey = loadPublicKey(pubkeyfile.getBytes());
        PrivateKey privKey = loadPrivateKey(keyfile.getBytes(), null);
        String signature = signBase64(privKey, payload);
        return verifyBase64(pubKey, signature, payload);
    }

    private String sign(String payload, String keyfile) throws InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        PrivateKey privKey = loadPrivateKey(keyfile.getBytes(), null);
        String signature = signBase64(privKey, payload);

        return signature;
    }

}
