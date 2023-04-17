package com.example.restApi.Security.Services;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.example.restApi.Security.JWT.TokenBlacklistService;

@Service
public class InMemoryTokenBlacklistService implements TokenBlacklistService {

  private final Map<String, Boolean> tokenMap = new ConcurrentHashMap<>();

  @Override
  public void addTokenToBlacklist(String token) {
    tokenMap.put(token, true);
  }

  @Override
  public boolean isTokenBlacklisted(String token) {
    return tokenMap.containsKey(token);
  }
}
