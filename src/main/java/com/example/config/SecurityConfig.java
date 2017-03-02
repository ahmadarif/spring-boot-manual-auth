package com.example.config;

import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
 * Created by ARIF on 28-Feb-17.
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/tes", "/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()

//                .and().logout().logoutSuccessHandler(new LogoutSuccess()).permitAll() // logout ok, gak bisa langsung login, kecuali hit ke yang butuh role terlebih dahulu
                .and().logout().permitAll() // logout error 403, tapi auth aplikasi berjalan normal

                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

}