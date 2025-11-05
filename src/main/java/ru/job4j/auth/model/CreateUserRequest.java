package ru.job4j.auth.model;

public record CreateUserRequest (
    String firstName,
    String lastName,
    String email,
    String login,
    String password){
}
