package com.smart_ecomernce_api.smart_ecomernce_api.exception;

// ─── BadCredentialsException.java ────────────────────────────────────────────

public class BadCredentialsException extends RuntimeException {
    public BadCredentialsException(String message) {
        super(message);
    }
}