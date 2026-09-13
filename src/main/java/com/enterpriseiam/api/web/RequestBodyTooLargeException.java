package com.enterpriseiam.api.web;

import java.io.IOException;

/** A transport limit, distinct from bean validation after JSON has already been allocated. */
public final class RequestBodyTooLargeException extends IOException {
    public RequestBodyTooLargeException() {
        super("The request body exceeds the permitted size.");
    }

    /** Jackson and MVC wrap stream failures; retain their transport status without exposing parser details. */
    public static boolean causedBy(Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < 32; depth++) {
            if (current instanceof RequestBodyTooLargeException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
