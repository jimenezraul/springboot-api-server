package com.api_server.API.Server.dto;

public record MessageResponse(
        String message,
        String status,
        String data
) {
    // Constructor with two arguments, providing a default value for 'data'
    public MessageResponse(String message, String status) {
        this(message, status, null); // Assigns null to 'data' by default
    }
}