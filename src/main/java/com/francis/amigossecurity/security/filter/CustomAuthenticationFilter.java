package com.francis.amigossecurity.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        /*
        for json, use object mapper code
         try{
                    LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);
                    return getAuthenticationManager().authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    loginRequest.getEmail(),
                                    loginRequest.getPassword(),
                                    new ArrayList<>()
                            )
                    );
                }catch (IOException e){
                    throw new RuntimeException(e);
                }
        */
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("username is {}", username);
        log.info("password is {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override //token generator
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        // copy auth0 from pom.xml
        User user = (User) authentication.getPrincipal(); //from security
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //get secret from environment variable
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) //get time from env too, shorter time
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles",user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) //get time from env too, longer time
                .withIssuer(request.getRequestURL().toString()) //no roles here
                .sign(algorithm);

//        String access_token = Jwts.builder().setSubject(user.getUsername())
//                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
//                .claim("roles",user.getAuthorities().stream()
//                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
//                .setIssuer(request.getRequestURL().toString())
//                .signWith(SignatureAlgorithm.HS512,"secret")
//                .compact();
//
//        String refresh_token = Jwts.builder().setSubject(user.getUsername())
//                .setExpiration(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
//                .setIssuer(request.getRequestURL().toString())
//                .signWith(SignatureAlgorithm.HS512,"secret")
//                .compact();

//        response.setHeader("access_token",access_token);  Actual way
//        response.setHeader("refresh_token",refresh_token); Actual way
        Map<String,String> tokens = new HashMap<>(); //not to use
        tokens.put("access_token",access_token);
        tokens.put("refresh_token",refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}
