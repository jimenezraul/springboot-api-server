package com.api_server.API.Server.exception;

import java.time.LocalDateTime;

public record ErrorDetails(String timestamp, String message, String details) {
    public ErrorDetails(LocalDateTime timestamp, String message, String details) {
        this(timestamp.toString(), message, details);
    }
}
