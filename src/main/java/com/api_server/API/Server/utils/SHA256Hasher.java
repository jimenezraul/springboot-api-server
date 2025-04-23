package com.api_server.API.Server.utils;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public class SHA256Hasher {

    public static String hash(String token) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));

        // Convert byte array to Base64 string for easier storage
        return Base64.getEncoder().encodeToString(hash);
    }
}
