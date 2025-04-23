package com.api_server.API.Server.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class NullFieldException extends RuntimeException {
    public NullFieldException(String message) {
        super(message);
    }
}