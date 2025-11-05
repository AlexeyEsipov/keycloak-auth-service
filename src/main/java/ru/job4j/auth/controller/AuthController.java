package ru.job4j.auth.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import ru.job4j.auth.model.CreateUserRequest;
import ru.job4j.auth.model.LoginPassword;
import ru.job4j.auth.model.UserResponse;
import ru.job4j.auth.service.UserService;

import java.util.Objects;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<UserResponse> getAuthToken(@RequestBody LoginPassword user) {
        UserResponse userResponse = userService.authUser(user);
        return userResponse == null
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
                : ResponseEntity.status(HttpStatus.OK).body(userResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<HttpStatus> createUser(@RequestBody CreateUserRequest user) {
        String userId = userService. registrationUser(user);
        return userId == null
                ? ResponseEntity.status(HttpStatus.CONFLICT).build()
                : ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<UserResponse> refreshToken(@CookieValue(value = "RT", required = false) String oldRefreshTokenCookie,
                                                      @RequestHeader(value = "refresh-token", required = false) String refreshTokenHeader) {
        if (Objects.isNull(oldRefreshTokenCookie) && Objects.isNull(refreshTokenHeader)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        String refreshToken = Objects.isNull(oldRefreshTokenCookie) ? refreshTokenHeader : oldRefreshTokenCookie;
        return ResponseEntity.status(HttpStatus.OK).body(userService.refresh(refreshToken));
    }

    @DeleteMapping("/delete/{appUserId}")
    public ResponseEntity<HttpStatus> deleteUserByUserName(@PathVariable String appUserId, @AuthenticationPrincipal Jwt jwt) {
        String token = jwt.getTokenValue();
        userService.deleteUser(appUserId, token);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/logout")
    public ResponseEntity<HttpStatus> logoutUser(@AuthenticationPrincipal Jwt jwt) {
        String userUUID = jwt.getSubject();
        userService.logout(userUUID);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
