package com.example.restApi.Security.JWT;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtLogoutHandler implements LogoutSuccessHandler {

  private Map<String, String> tokenBlacklist = new ConcurrentHashMap<>();

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    String authorizationHeader = request.getHeader("Authorization");

    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      String token = authorizationHeader.substring(7);
      tokenBlacklist.put(token, "expired");
    }
    response.setStatus(HttpServletResponse.SC_OK);
    // TODO Auto-generated method stub
    // throw new UnsupportedOperationException("Unimplemented method
    // 'onLogoutSuccess'");
  }

  public boolean isTokenExpired(String token) {
    return tokenBlacklist.containsKey(token);
  }

}
