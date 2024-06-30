package com.example.securityDemo.Config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration      // tells spring provides application context to this class
@EnableWebSecurity      // enable web security to access in this application
public class SecurityConfig {
    @Bean
        // mark as spring bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        //Spring Security does not create or use HTTP sessions for storing authentication details
        // beneficial for scalable and secure RESTful APIs where each request is authenticated independently without relying on server-side session storage.
        // so session id won't show
        http.sessionManagement(session
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(withDefaults());       // this is form based authentication(default)
        http.httpBasic(withDefaults());     // this is pop up based authentication(basic authentication)
        return http.build();
    }



    //in memory authentication as storing user details in the memory
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}password1")                        //{noop} is to encrypt password
                .roles("USER")
                .build();

        UserDetails admin1 = User.withUsername("admin")
                .password("{noop}adminPassword")                        //{noop} is to encrypt password
                .roles("ADMIN")
                .build();

        // test using in memory data( no need for database)
        // InMemoryUserDetailsManager needs object of type 'UserDetails' as arguments
        // we can pass any number of objects as arguments
        return new InMemoryUserDetailsManager(user1,admin1);
    }
}
