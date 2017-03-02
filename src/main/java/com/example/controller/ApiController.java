package com.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

/**
 * Created by ARIF on 28-Feb-17.
 */
@RestController
public class ApiController {

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/tes")
    public Map tes() {
        Map<String, Object> map = new HashMap<>();
        map.put("message", "Hello world!");
        map.put("time", new Date().toString());
        return map;
    }

    @PostMapping("/login")
    public Map login() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        Authentication newAuth = new UsernamePasswordAuthenticationToken("ahmadarif", auth.getCredentials(), authorities);
        SecurityContextHolder.getContext().setAuthentication(newAuth);

        Map<String, Object> map = new HashMap<>();
        map.put("message", "Logged in user!");
        return map;
    }

    @GetMapping("/roles")
    public Object roles(Authentication auth) {
        return auth.getAuthorities();
    }

    @GetMapping("/user")
    public Object user(Authentication auth) {
        return auth;
    }

}