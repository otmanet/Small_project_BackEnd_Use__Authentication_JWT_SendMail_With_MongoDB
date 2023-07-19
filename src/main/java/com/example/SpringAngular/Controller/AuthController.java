package com.example.SpringAngular.Controller;


import com.example.SpringAngular.Model.ERole;
import com.example.SpringAngular.Model.Role;
import com.example.SpringAngular.Model.User;
import com.example.SpringAngular.Repository.RoleRepository;
import com.example.SpringAngular.Repository.UserRepository;
import com.example.SpringAngular.Security.JWT.JwtUtils;
import com.example.SpringAngular.Security.Services.EmailService;
import com.example.SpringAngular.Security.Services.UserDetailsImpl;
import com.example.SpringAngular.payload.request.LoginRequest;
import com.example.SpringAngular.payload.request.ResetPassword;
import com.example.SpringAngular.payload.request.SignupRequest;
import com.example.SpringAngular.payload.response.JwtResponse;
import com.example.SpringAngular.payload.response.MessageResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.aggregation.Aggregation;
import org.springframework.data.mongodb.core.aggregation.AggregationResults;
import org.springframework.data.mongodb.core.aggregation.MatchOperation;
import org.springframework.data.mongodb.core.aggregation.ProjectionOperation;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*",exposedHeaders="Access-Control-Allow-Origin", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

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

    @Autowired
    private MongoTemplate mongoTemplate;

    @Value("${otmane.app.jwtSecret}")
    private String jwtSecret;

    @Value("${otmane.app.jwtExpirationMs}")
    private  int jwtExpirationMs;

    @Autowired
     private EmailService emailservice;
    Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            return ResponseEntity.ok(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));
        } catch (Exception e) {
            logger.error("error it's {} :", e.getMessage());
        }
        return null;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
    
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error : Username is Already taken !"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error : Email is Already in user !"));
        }

        // Create new user's account
        User user = new User(signupRequest.getUsername(), signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()));
        Set<String> strRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error : Role is not found1."));
            roles.add(userRole);
            // Role userRole = roleRepository.findByName(ERole.ROLE_USER);
            // roles.add(userRole);
            // user.setRoles(roles);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role admin is not found2."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role mod is not found3."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found4."));
                        roles.add(userRole);
                }
            });

        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @GetMapping(value = {"/logout"})
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String token = jwtUtils.extractJwtFromRequest(request);

        if (StringUtils.hasText(token)) {
            jwtUtils.blacklistJwtToken(token);
        }
        return ResponseEntity.ok("Logout successful");
    }
    // send mail for reset Password :

    @GetMapping("/sendMail")
    public ResponseEntity<?> sendMailResetPassword(@RequestBody ResetPassword resetPassword){
        String emailSend = resetPassword.getEmailSend();
      
        /*Query query = new Query();
        ProjectionOperation projection = Aggregation.project("username", "isDeleted"); // Specify the fields you want to retrieve
        query.addCriteria(Criteria.where("email").is(emailSend)).with(projection);
        User user=mongoTemplate.findOne(query,User.class);*/
        MatchOperation matchOperation = Aggregation.match(Criteria.where("email").is(emailSend));

        ProjectionOperation projectionOperation = Aggregation.project("username", "isDeleted","email"); // Specify the fields you want to retrieve

        Aggregation aggregation = Aggregation.newAggregation(matchOperation, projectionOperation);

        AggregationResults<User> aggregationResults = mongoTemplate.aggregate(aggregation, "users", User.class);

        User userProjection = aggregationResults.getUniqueMappedResult();
        //  return ResponseEntity.ok(userProjection);
        if (userProjection != null) {
           
            // Handle user not found scenario
            if(userProjection.isDeleted() == false ){
                System.out.println("*********************************qsd");
                // Generate a token for the user
                 String token = Jwts.builder()
                         .setSubject((userProjection.getUsername()))
                         .setIssuedAt(new Date())
                         .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                         .signWith(SignatureAlgorithm.HS512, jwtSecret)
                         .compact();
                emailservice.sendMail(userProjection.getEmail(),token);
                // Return the user and the generated token in the response:
                return ResponseEntity.ok(new JwtResponse(token,
                        userProjection.getId(),
                        userProjection.getUsername(),
                        userProjection.getEmail(),
                        null));

            }
            return ResponseEntity.ok(userProjection);

        }else{
            return ResponseEntity.notFound().build();
        }


    }
    // Define an endpoint to handle password reset requests
    @PostMapping("/password-reset")
    public ResponseEntity<?> requestPasswordReset(@RequestParam("token") String  token,@RequestBody ResetPassword resetPassword){
        
         // get date Experation token  :
        Date date_exp= jwtUtils.getExpirationDateFromToken(token);
       
        Date date = new Date();
        // Compare dates using compareTo() method
        int comparison = date_exp.compareTo(date);

        if(comparison > 0){

            /*return  ResponseEntity.ok("token not expired yet");*/
            boolean valideToken=jwtUtils.validateJwtToken(token);
            if(valideToken==true){
            	String Username=  jwtUtils.getUserNameFromJwtToken(token);
            	 MatchOperation matchOperation = Aggregation.match(Criteria.where("username").is(Username));

                 ProjectionOperation projectionOperation = Aggregation.project("id","username", "isDeleted","email");
                 Aggregation aggregation = Aggregation.newAggregation(matchOperation, projectionOperation);

                 AggregationResults<User> aggregationResults = mongoTemplate.aggregate(aggregation, "users", User.class);

                 User userProjection = aggregationResults.getUniqueMappedResult();
                 
                 userProjection.setPassword(encoder.encode(resetPassword.getPassword()));
                 User userPassword = mongoTemplate.save(userProjection);
                return  ResponseEntity.ok("token it's exist : "+userPassword.getPassword());
            }
        }else{
            return ResponseEntity.ok("Token it's expired");
        }
        return null;
    }
   
}
