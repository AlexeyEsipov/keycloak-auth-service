package ru.job4j.auth.model;

public record UserResponse (String accessToken, String idToken, String refreshToken) {}
