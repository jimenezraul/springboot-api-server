package com.api_server.API.Server.utils;

import java.security.SecureRandom;

public class CustomIDGenerator {
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String generateCustomID(String PREFIX) {
        StringBuilder sb = new StringBuilder();
        sb.append(PREFIX);
        for (int i = 0; i < 34; i++) {
            sb.append(ALPHANUMERIC.charAt(RANDOM.nextInt(ALPHANUMERIC.length())));
        }
        return sb.toString();
    }
}