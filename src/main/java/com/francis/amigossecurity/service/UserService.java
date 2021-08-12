package com.francis.amigossecurity.service;

import com.francis.amigossecurity.model.Role;
import com.francis.amigossecurity.model.UserEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public interface UserService {
    UserEntity saveUser(UserEntity userEntity);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    UserEntity getUser(String username);
    List<UserEntity> getUsers(); //page of users in the real world
    void refreshToken(HttpServletRequest request, HttpServletResponse response)  throws IOException;
}
