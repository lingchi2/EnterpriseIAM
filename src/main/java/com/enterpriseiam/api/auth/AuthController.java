package com.enterpriseiam.api.auth;

import com.enterpriseiam.security.auth.AuthenticationService;
import com.enterpriseiam.security.jwt.IamJwtAuthenticationToken;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Bearer credentials are returned only in JSON and are never persisted in browser cookies. */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthenticationService authentication;
    private final TokenResponseMapper tokens;

    public AuthController(AuthenticationService authentication, TokenResponseMapper tokens) {
        this.authentication = authentication;
        this.tokens = tokens;
    }

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return tokenResponse(tokens.toResponse(authentication.login(request.email(), request.password())));
    }

    @PostMapping(value = "/refresh", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return tokenResponse(tokens.toResponse(authentication.refresh(request.refreshToken())));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(IamJwtAuthenticationToken principal) {
        authentication.logout(principal);
        return ResponseEntity.noContent().header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache").build();
    }

    private static ResponseEntity<TokenResponse> tokenResponse(TokenResponse response) {
        return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache").body(response);
    }
}
