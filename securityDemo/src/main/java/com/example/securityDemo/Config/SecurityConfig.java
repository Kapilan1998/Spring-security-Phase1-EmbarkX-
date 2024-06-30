package com.example.securityDemo.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration      // tells spring provides application context to this class
@EnableWebSecurity      // enable web security to access in this application
public class SecurityConfig {
    @Bean       // mark as spring bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        //Spring Security does not create or use HTTP sessions for storing authentication details
        // beneficial for scalable and secure RESTful APIs where each request is authenticated independently without relying on server-side session storage.
        // so session id won't show
        http.sessionManagement(session
                ->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(withDefaults());       // this is form based authentication(default)
        http.httpBasic(withDefaults());     // this is pop up based authentication(basic authentication)
        return http.build();
    }
}
