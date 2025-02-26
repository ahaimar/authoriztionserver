package io.getarrays.authoriztionserver.exception;

public class ApiException extends RuntimeException {


    public ApiException(String message) {
        super(message);
    }

    public ApiException(String message, Throwable cause) {
        super(message, cause);
    }

    public int getStatusCode() {
        return 500;
    }
}
