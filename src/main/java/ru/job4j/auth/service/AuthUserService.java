package ru.job4j.auth.service;

import jakarta.ws.rs.NotAuthorizedException;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import ru.job4j.auth.model.TokenResponse;
import ru.job4j.auth.model.UserResponse;

import java.net.URI;

@Service
public class AuthUserService {

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String serverURL;

    @Value("${keycloak.auth.client}")
    private String authClientID;

    @Value("${keycloak.auth.secret}")
    private String authClientSecret;

    @Value("${keycloak.token.endpoint}")
    private String tokenEndpoint;

    private final RestClient restClient;

    public AuthUserService(RestClient restClient) {
        this.restClient = restClient;
    }

    public UserResponse authUserWithoutSession(String userName, String password) {
        String accessToken;
        String refreshToken;
        String idToken;
        try (Keycloak keycloakUser = KeycloakBuilder.builder()
                .serverUrl(serverURL)
                .realm(realm)
                .grantType(OAuth2Constants.PASSWORD)
                .clientId(authClientID)
                .clientSecret(authClientSecret)
                .scope("openid")
                .username(userName)
                .password(password)
                .build()) {
            TokenManager tm = keycloakUser.tokenManager();
            try {
                accessToken = tm.getAccessTokenString();
            } catch (NotAuthorizedException e) {
                e.printStackTrace();
                return null;
            }
            refreshToken = tm.refreshToken().getRefreshToken();
            idToken = tm.getAccessToken().getIdToken();
        }
        return new UserResponse(accessToken, idToken, refreshToken);
    }

    public UserResponse authUser(String userName, String password) {
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("grant_type", OAuth2Constants.PASSWORD);
        mapForm.add("client_id", authClientID);
        mapForm.add("client_secret", authClientSecret);
        mapForm.add("username", userName);
        mapForm.add("password", password);
        mapForm.add("scope", "openid profile email");
        ResponseEntity<TokenResponse> response = restClient.post()
                .uri(URI.create(tokenEndpoint))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(mapForm)
                .retrieve()
                .toEntity(TokenResponse.class);
        TokenResponse token = response.getBody();
        return new UserResponse(token.getAccessToken(), token.getIdToken(), token.getRefreshToken());
    }


    public UserResponse refresh(String userRefreshToken) {
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("grant_type", OAuth2Constants.REFRESH_TOKEN);
        mapForm.add("client_id", authClientID);
        mapForm.add("client_secret", authClientSecret);
        mapForm.add("refresh_token", userRefreshToken);
        TokenResponse tokenResponse = restClient.post()
                .uri(tokenEndpoint)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(mapForm)
                .retrieve()
                .body(TokenResponse.class);
        String accessToken = tokenResponse.getAccessToken();
        String refreshToken = tokenResponse.getRefreshToken();
        String idToken = tokenResponse.getIdToken();
        return new UserResponse(accessToken, idToken, refreshToken);
    }
}
