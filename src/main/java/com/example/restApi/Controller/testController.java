package com.example.restApi.Controller;

import java.nio.file.AccessDeniedException;
import java.nio.file.attribute.UserPrincipal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.restApi.Security.JWT.AuthEntryPointJwt;
import com.example.restApi.Security.JWT.JwtUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@CrossOrigin(origins = "*", maxAge = 1500)
@RestController
@RequestMapping("/api/test")
public class testController {

  @Autowired
  private JwtUtils JwtUtils;

  @GetMapping("/logout")
  public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse res) {
    // TODO: Invalidate JWT token here
    // Invalidate JWT token
    String authHeader = JwtUtils.extractJwtFromRequest(request);
    if (authHeader != null) {
      // System.out.println("authHeader :"+ authHeader);
      JwtUtils.addToBlacklist(authHeader);
    }

    // Clear session
    // HttpSession session = request.getSession(false);
    // if (session != null) {
    // session.invalidate();
    // }

    // Clear cookies
    // Cookie[] cookies = request.getCookies();
    // if (cookies != null) {
    // for (Cookie cookie : cookies) {
    // cookie.setMaxAge(0);
    // cookie.setValue("");
    // cookie.setPath("/");
    // res.addCookie(cookie);
    // }
    // }
    return ResponseEntity.ok("Logout successful");
  }

  @GetMapping("/all")
  public ResponseEntity<?> allAccess(HttpServletRequest httpRequest) {
    try {
      String token = JwtUtils.extractJwtFromRequest(httpRequest);
      // JwtUtils.isTokenExpired(token)
      return ResponseEntity.ok(JwtUtils.getClaims(token).getExpiration());

      // return ResponseEntity.ok("token expired :"+JwtUtils.isTokenExpired(token));
    } catch (ExpiredJwtException e) {
      // TODO: handle exception
      return ResponseEntity.ok("you should be logout and login");
    }

  }

  @GetMapping("/admin")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<?> adminAccess(HttpServletResponse res, HttpServletRequest req) {

    String token = JwtUtils.extractJwtFromRequest(req);
    if (JwtUtils.isTokenExpired(token) == false) {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      // verify this authentication it's instance the class
      // AnonymousAuthenticationToken
      if (!(authentication instanceof AnonymousAuthenticationToken)) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String username = userDetails.getUsername();
        return ResponseEntity.ok("Welcome " + username + " this is the admin board");
      } else {
        // res.sendError(HttpServletResponse.SC_FORBIDDEN,"Forbidden");
        // throw new AccessDeniedException("You are not authorized to access this
        // page.");
        return ResponseEntity.ok("Forbidden");
      }

    } else {
      // return 401 Unauthorized response
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
    }

  }

  @GetMapping("/user")
  @PreAuthorize("hasRole('USER') ")
  public String userAccess() {
    return "User Content (Role User).";
  }

  @GetMapping("/mod")
  @PreAuthorize("hasRole('MODERATOR')")
  public String moderatorAccess() {
    return "Moderator Board (Role Moderator).";
  }

}
// //verfy authenticated :
// try{

// String authorizationHeader = httpRequest.getHeader("Authorization");
// String token = authorizationHeader.substring(7); // remove "Bearer " from the
// header
// Claims claims = Jwts.parserBuilder()
// .setSigningKey(Keys.hmacShaKeyFor("yourSecretKey".getBytes()))
// .build()
// .parseClaimsJws(token)
// .getBody();
// // verify if the token is expired
// if(claims.getExpiration().before(new Date()))
// {
// return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is
// expired.");
// }return ResponseEntity.ok("Public Content For User.");}catch(
// Exception e)
// {
// return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized.");
// }

// another method inside class jwtUtils :
// public class JWTUtils {

// private final String SECRET_KEY = "yourSecretKey";

// public String extractJwtFromRequest(HttpServletRequest request) {
// String authorizationHeader = request.getHeader("Authorization");
// if (authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
// {
// return authorizationHeader.substring(7);
// }
// return null;
// }

// public Claims getClaims(String token) {
// return Jwts.parserBuilder()
// .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()))
// .build()
// .parseClaimsJws(token)
// .getBody();
// }

// public boolean isTokenExpired(String token) {
// Claims claims = getClaims(token);
// return claims.getExpiration().before(new Date());
// }
// }
