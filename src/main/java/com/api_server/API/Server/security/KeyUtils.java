package com.api_server.API.Server.security;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Utility class for managing RSA key pairs used for access and refresh tokens.
 * This class retrieves RSA keys from application properties, decodes them, and provides
 * methods to access the public and private keys for both access and refresh tokens.
 *
 * The keys are expected to be Base64-encoded strings stored in the application properties.
 *
 * Annotations:
 * - @Component: Marks this class as a Spring-managed component.
 * - @Slf4j: Enables logging using the SLF4J framework.
 */
@Component
@Slf4j
public class KeyUtils {

    /**
     * Base64-encoded private key for access tokens, injected from application properties.
     */
    @Value("${access-token.private}")
    private String accessTokenPrivateKey;

    /**
     * Base64-encoded public key for access tokens, injected from application properties.
     */
    @Value("${access-token.public}")
    private String accessTokenPublicKey;

    /**
     * Base64-encoded private key for refresh tokens, injected from application properties.
     */
    @Value("${refresh-token.private}")
    private String refreshTokenPrivateKey;

    /**
     * Base64-encoded public key for refresh tokens, injected from application properties.
     */
    @Value("${refresh-token.public}")
    private String refreshTokenPublicKey;

    /**
     * Cached KeyPair for access tokens to avoid redundant decoding.
     */
    private KeyPair _accessTokenKeyPair;

    /**
     * Cached KeyPair for refresh tokens to avoid redundant decoding.
     */
    private KeyPair _refreshTokenKeyPair;

    /**
     * Retrieves the KeyPair for access tokens. If not already cached, it decodes
     * the keys from the Base64-encoded strings and creates the KeyPair.
     *
     * @return KeyPair for access tokens.
     */
    private KeyPair getAccessTokenKeyPair() {
        if (Objects.isNull(_accessTokenKeyPair)) {
            _accessTokenKeyPair = getKeyPair(accessTokenPublicKey, accessTokenPrivateKey);
        }
        return _accessTokenKeyPair;
    }

    /**
     * Retrieves the KeyPair for refresh tokens. If not already cached, it decodes
     * the keys from the Base64-encoded strings and creates the KeyPair.
     *
     * @return KeyPair for refresh tokens.
     */
    private KeyPair getRefreshTokenKeyPair() {
        if (Objects.isNull(_refreshTokenKeyPair)) {
            _refreshTokenKeyPair = getKeyPair(refreshTokenPublicKey, refreshTokenPrivateKey);
        }
        return _refreshTokenKeyPair;
    }

    /**
     * Decodes Base64-encoded public and private keys and creates a KeyPair.
     *
     * @param publicKeyContent Base64-encoded public key.
     * @param privateKeyContent Base64-encoded private key.
     * @return Decoded KeyPair.
     * @throws RuntimeException if the keys cannot be decoded or are invalid.
     */
    private KeyPair getKeyPair(String publicKeyContent, String privateKeyContent) {
        KeyPair keyPair;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Decode the base64-encoded key content
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            keyPair = new KeyPair(publicKey, privateKey);
            return keyPair;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves the RSA public key for access tokens.
     *
     * @return RSAPublicKey for access tokens.
     */
    public RSAPublicKey getAccessTokenPublicKey() {
        return (RSAPublicKey) getAccessTokenKeyPair().getPublic();
    }

    /**
     * Retrieves the RSA private key for access tokens.
     *
     * @return RSAPrivateKey for access tokens.
     */
    public RSAPrivateKey getAccessTokenPrivateKey() {
        return (RSAPrivateKey) getAccessTokenKeyPair().getPrivate();
    }

    /**
     * Retrieves the RSA public key for refresh tokens.
     *
     * @return RSAPublicKey for refresh tokens.
     */
    public RSAPublicKey getRefreshTokenPublicKey() {
        return (RSAPublicKey) getRefreshTokenKeyPair().getPublic();
    }

    /**
     * Retrieves the RSA private key for refresh tokens.
     *
     * @return RSAPrivateKey for refresh tokens.
     */
    public RSAPrivateKey getRefreshTokenPrivateKey() {
        return (RSAPrivateKey) getRefreshTokenKeyPair().getPrivate();
    }
}