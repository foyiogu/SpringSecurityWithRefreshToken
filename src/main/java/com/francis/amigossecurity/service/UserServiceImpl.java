package com.francis.amigossecurity.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.francis.amigossecurity.model.Role;
import com.francis.amigossecurity.model.UserEntity;
import com.francis.amigossecurity.repository.RoleRepository;
import com.francis.amigossecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
@Service
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByUsername(username);
        if (userEntity == null){
            log.info("User not found");
            throw new UsernameNotFoundException("user not found");
        }else {
            log.info("user found");
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        userEntity.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new User(userEntity.getUsername(),userEntity.getPassword(), authorities); //spring security user
    }

    @Override
    public UserEntity saveUser(UserEntity userEntity) {
        log.info("saving new user {} info", userEntity.getName());
        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
        return userRepository.save(userEntity);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role {} info", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        //add validation where necessary
        log.info("adding role {} to user {}", roleName, username);
        UserEntity userEntity = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);
        userEntity.getRoles().add(role);
    }

    @Override
    public UserEntity getUser(String username) {
        log.info("getting user {}",  username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<UserEntity> getUsers() {
        log.info("getting all users");
        return userRepository.findAll();
    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //get secret from environment variable, keep in utility class
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();

                UserEntity userEntity = userRepository.findByUsername(username);

                String access_token = JWT.create()
                        .withSubject(userEntity.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) //get time from env too, shorter time
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",userEntity.getRoles().stream()
                                .map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String,String> tokens = new HashMap<>(); //not to use
                tokens.put("access_token",access_token);
                tokens.put("refresh_token",refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            }catch (Exception e){
                response.setHeader("error", e.getMessage());
//                    response.sendError(FORBIDDEN.value()); //check . Correct

                //wrong, for test
                response.setStatus(FORBIDDEN.value());
                Map<String,String> error = new HashMap<>(); //not to use
                error.put("error_message",e.getMessage()); //wrong, for test
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        }else {
            throw new RuntimeException("refresh token is missing");
        }

    }
}
