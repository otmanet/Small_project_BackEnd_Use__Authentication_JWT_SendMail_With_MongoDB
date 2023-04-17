package com.example.restApi.Controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.restApi.Models.*;
import com.example.restApi.Payload.Request.LoginRequest;
import com.example.restApi.Payload.Request.SignupRequest;
import com.example.restApi.Payload.Response.JwtResponse;
import com.example.restApi.Payload.Response.MessageResponse;
import com.example.restApi.Repository.RoleRepository;
import com.example.restApi.Repository.UserRepository;
import com.example.restApi.Security.JWT.JwtUtils;
import com.example.restApi.Security.Services.UserDetailsImpl;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

@CrossOrigin(origins = "*", exposedHeaders = "Access-Control-Allow-Origin", maxAge = 1500)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  Logger logger = LoggerFactory.getLogger(AuthController.class);
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping(value = { "/logout" })
  public ResponseEntity<?> logout(HttpServletRequest request) {
    String token = jwtUtils.extractJwtFromRequest(request);
    if (StringUtils.hasText(token)) {
      jwtUtils.blacklistJwtToken(token);
    }
    return ResponseEntity.ok("Logout successful");

  }

  @RequestMapping(value = { "/signun" }, method = RequestMethod.POST)
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
    // if (userRepository.existsByUsername(signupRequest.getUsername())) {
    // return ResponseEntity
    // .badRequest()
    // .body(new MessageResponse("Error : Username is Already taken !"));
    // }
    // if (userRepository.existsByEmail(signupRequest.getEmail())) {
    // return ResponseEntity
    // .badRequest()
    // .body(new MessageResponse("Error : Email is Already in user !"));
    // }

    // // Create new user's account
    // User user = new User(signupRequest.getUsername(), signupRequest.getEmail(),
    // encoder.encode(signupRequest.getPassword()));
    // Set<String> strRoles = signupRequest.getRoles();
    // Set<Role> roles = new HashSet<>();

    // if (strRoles == null) {
    // Role userRole = roleRepository.findByName(ERole.ROLE_USER)
    // .orElseThrow(() -> new RuntimeException("Error : Role is not found1."));
    // roles.add(userRole);
    // // Role userRole = roleRepository.findByName(ERole.ROLE_USER);
    // // roles.add(userRole);
    // // user.setRoles(roles);
    // } else {
    // strRoles.forEach(role -> {
    // switch (role) {
    // case "admin":
    // Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
    // .orElseThrow(() -> new RuntimeException("Error: Role admin is not found2."));
    // roles.add(adminRole);

    // break;
    // case "mod":
    // Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
    // .orElseThrow(() -> new RuntimeException("Error: Role mod is not found3."));
    // roles.add(modRole);

    // break;
    // default:
    // Role userRole = roleRepository.findByName(ERole.ROLE_USER)
    // .orElseThrow(() -> new RuntimeException("Error: Role is not found4."));
    // roles.add(userRole);
    // }
    // });

    // }
    // user.setRoles(roles);
    // userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  @RequestMapping(value = { "/signin" }, method = RequestMethod.POST)
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    try {
      Authentication authentication = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
      // this is for checked user it's existe in DB ,you're essentially
      // telling Spring Security that the current user is now authenticated with the
      // provided credentials.
      SecurityContextHolder.getContext().setAuthentication(authentication);
      // generate token for this user
      String JWT = jwtUtils.generateJwtToken(authentication);
      UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
      List<String> roles = userDetails.getAuthorities().stream()
          .map(item -> item.getAuthority())
          .collect(Collectors.toList());
      return ResponseEntity.ok(new JwtResponse(JWT,
          userDetails.getId(),
          userDetails.getUsername(),
          userDetails.getEmail(),
          roles));
    } catch (Exception e) {
      // TODO: handle exception
      logger.error(("error it's {}"), e.getMessage());
    }
    return null;
  }

}
