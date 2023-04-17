package com.example.restApi.Security.JWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.restApi.Security.Services.UserDetailsImpl;
import com.example.restApi.Security.JWT.TokenBlacklistService;

import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

//JwtUtils provides methods for generating, parsing, validating JWT
@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${otmane.app.jwtSecret}")
  private String jwtSecret;

  @Value("${otmane.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  private TokenBlacklistService tokenBlacklistService;

  // Inject a RedisTemplate to store the invalidated tokens in Redis.
  @Autowired
  private RedisTemplate<String, String> redisTemplate;
  private final String BLACKLIST_PREFIX = "jwt-blacklist:";

  public String generateJwtToken(Authentication authentication) {
    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

    return Jwts.builder()
        .setSubject((userPrincipal.getUsername()))
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(SignatureAlgorithm.HS512, jwtSecret)
        .compact();

  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;

  }

  public String extractJwtFromRequest(HttpServletRequest request) {
    String authorizationHeader = request.getHeader("Authorization");
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      return authorizationHeader.substring(7);
    }
    return null;
  }

  public Claims getClaims(String token) {
    return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
  }

  public boolean isTokenExpired(String token) {
    Claims claims = getClaims(token);
    return claims.getExpiration().before(new Date());
  }

  // Method to add JWT token to blacklist
  public void addToBlacklist(String token) {

    // Calculate the expiration time for the token
    Instant expiration = Instant.now().plusSeconds(jwtExpirationMs);

    // Store the token in Redis with a TTL equal to the token's remaining time to
    // live.
    System.out.println("#####token  #### :" + token);
    redisTemplate.opsForValue().set(BLACKLIST_PREFIX + token, "", Duration.between(Instant.now(), expiration));
    // System.out.println("#####token 2 #### :" + token);

    // String key = "blacklist:" + token;
    // redisTemplate.opsForValue().set(key, "");
    // Set expiration time to match the token expiration
    // redisTemplate.expire(key, getExpiration(token), TimeUnit.MILLISECONDS);
  }

  // private long getExpiration(String token) {
  // Claims claims =
  // Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
  // Date expiration = claims.getExpiration();
  // return expiration.getTime() - System.currentTimeMillis();
  // }

  // Method to check if a JWT token is blacklisted
  public boolean isBlacklisted(String token) {
    return redisTemplate.hasKey(BLACKLIST_PREFIX + token);
  }

  // public void addToBlacklist(String token) {
  // redisTemplate.opsForSet().add("jwt:blacklist", token);
  // }

  public void blacklistJwtToken(String token) {
    tokenBlacklistService.addTokenToBlacklist(token);
  }
}
