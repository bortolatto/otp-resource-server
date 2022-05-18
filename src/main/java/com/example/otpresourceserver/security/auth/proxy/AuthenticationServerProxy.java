package com.example.otpresourceserver.security.auth.proxy;

import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@RequiredArgsConstructor
public class AuthenticationServerProxy {

    private final RestTemplate rest;

    @Value("${auth.server.base.url}")
    private String baseUrl;

    public void sendAuth(String username, String password, String clientId, String clientSecret) {
        String url = baseUrl + "/user/auth";
        UserDTO body = UserDTO.builder().username(username).password(password).build();
        HttpEntity<UserDTO> request = buildHeader(clientId, clientSecret, body);
        rest.postForEntity(url, request, Void.class);
    }

    public boolean sendOTP(String username, String code, String clientId, String clientSecret) {
        String url = baseUrl + "/otp/check";
        UserDTO body = UserDTO.builder().username(username).code(code).build();
        HttpEntity<UserDTO> request = buildHeader(clientId, clientSecret, body);
        ResponseEntity<Void> response = rest.postForEntity(url, request, Void.class);

        return response.getStatusCode().equals(HttpStatus.OK);
    }

    private HttpEntity<UserDTO> buildHeader(String clientId, String clientSecret, UserDTO body) {
        HttpHeaders httpHeaders = new HttpHeaders();
        String base64Credentials = Base64.getEncoder().encodeToString(String.format("%s:%s", clientId, clientSecret).getBytes());
        httpHeaders.add("Authorization", String.format("Basic %s", base64Credentials));
        return new HttpEntity<>(body, httpHeaders);
    }
}