package io.getarrays.authoriztionserver.security;

import com.nimbusds.jose.jwk.RSAKey;
import io.getarrays.authoriztionserver.exception.ApiException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

@Slf4j
@Component
public class KeyUtils {

    private static final String RSA = "RSA";

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @Value("${keys.private}")
    private String privateKey;

    @Value("${keys.public}")
    private String publicKey;

    public RSAKey getRSAKeyPair() {
        return generateRSAKeyPair(privateKey, publicKey);
    }

    private RSAKey generateRSAKeyPair(String privateKeyName, String publicKeyName) {
        Path keyDirectory = Paths.get("src", "main", "resources", "keys");

        verifyKeyDirectory(keyDirectory);

        if (!activeProfile.equalsIgnoreCase("prod") &&
                Files.exists(keyDirectory.resolve(privateKeyName)) &&
                Files.exists(keyDirectory.resolve(publicKeyName))) {
            log.info("RSA key already exists. Loading keys from file paths {}, {}", publicKeyName, privateKeyName);

            File privateKeyFile = keyDirectory.resolve(privateKeyName).toFile();
            File publicKeyFile = keyDirectory.resolve(publicKeyName).toFile();

            try {
                KeyFactory keyFactory = KeyFactory.getInstance(RSA);

                // Load Public Key
                byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

                // Load Private Key
                byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

                var keyId = UUID.randomUUID().toString();
                log.info("Loaded RSA key pair with keyId: {}", keyId);

                return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId).build();
            } catch (Exception e) {
                log.error("Error loading RSA keys: {}", e.getMessage(), e);
                throw new ApiException("Failed to load RSA keys: " + e.getMessage());
            }
        }

        if (activeProfile.equalsIgnoreCase("prod")) {
            throw new ApiException("Public and Private keys are missing in the production environment");
        }

        log.info("Generating new Public and Private keys: {}, {}", publicKeyName, privateKeyName);

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            // Save Private Key
            try (var fos = new FileOutputStream(keyDirectory.resolve(privateKeyName).toFile())) {
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
                fos.write(privateKeySpec.getEncoded());
            }

            // Save Public Key
            try (var fos = new FileOutputStream(keyDirectory.resolve(publicKeyName).toFile())) {
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
                fos.write(publicKeySpec.getEncoded());
            }

            return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
        } catch (Exception e) {
            log.error("Error generating RSA key pair: {}", e.getMessage(), e);
            throw new ApiException("Failed to generate RSA keys: " + e.getMessage());
        }
    }

    private void verifyKeyDirectory(Path keyDirectory) {
        if (!Files.exists(keyDirectory)) {
            try {
                Files.createDirectories(keyDirectory);
                log.info("Created directory: {}", keyDirectory);
            } catch (Exception e) {
                log.error("Failed to create directory: {}", e.getMessage(), e);
                throw new ApiException("Failed to create key directory: " + e.getMessage());
            }
        }
    }
}
