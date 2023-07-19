package com.example.SpringAngular.Security.JWT;

public interface TokenBlacklistService {
    void addTokenToBlacklist(String token);

    boolean isTokenBlacklisted(String token);
}
