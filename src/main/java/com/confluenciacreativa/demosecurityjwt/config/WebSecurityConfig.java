package com.confluenciacreativa.demosecurityjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic(withDefaults())
                .authorizeRequests()
                .antMatchers("/publico/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();
    }

    // (1) Spring Security's HTTP Basic Authentication support in is enabled bay default.
    // However, as soon as any servlet based configuration es provided, HTTP Basic must be explicitly provided.


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("jcabelloc").password("{noop}" + "secreto").roles("USER")
                .and()
                .withUser("mlopez").password("{noop}" + "secreto").roles("ADMIN");
    }
}
