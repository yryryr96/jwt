package com.cos.jwt.config.jwt;

public interface JwtProperties {

    String SECRET = "secret";
    int EXPIRATION_TIME = 1000 * 60 * 10; // 1초 * 60 * 10 -> 10분
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
