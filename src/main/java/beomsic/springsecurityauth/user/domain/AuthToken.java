package beomsic.springsecurityauth.user.domain;

public record AuthToken(String accessToken, String refreshToken) {}
