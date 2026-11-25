package com.phishguard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;

import java.util.Map;

/** Turns errors into simple JSON like {"error": "..."} so the web page can show a friendly message. */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return error(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, String>> tooLarge(MaxUploadSizeExceededException e) {
        return error(HttpStatus.PAYLOAD_TOO_LARGE, "The file is too large. The maximum upload size is 20 MB.");
    }

    @ExceptionHandler({MultipartException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, String>> unreadable(Exception e) {
        return error(HttpStatus.BAD_REQUEST, "The request could not be read. Please check the form and try again.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> unexpected(Exception e) {
        if (e instanceof ErrorResponse springError) {
            // Spring's own errors (404 not found, 405 wrong method, 415 wrong content type ...) keep their status.
            String detail = springError.getBody().getDetail();
            return error(springError.getStatusCode(), detail != null ? detail : "Request failed.");
        }
        log.error("Unexpected error", e);
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected server error. Please try again.");
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatusCode status, String message) {
        return ResponseEntity.status(status).body(Map.of("error", message));
    }
}
