package com.example.securityDemo.Config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration      // tells spring provides application context to this class
@EnableWebSecurity      // enable web security to access in this application
@EnableMethodSecurity       //enables method-level security to this application.
public class SecurityConfig {

    @Autowired
    DataSource dataSource;          // used for authentication and authorization.
    @Bean
        // mark as spring bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                // Allow all requests to the H2 console without authentication
                .requestMatchers("/h2-console/**").permitAll()
                // Require authentication for any other requests
                .anyRequest().authenticated());
        //Spring Security does not create or use HTTP sessions for storing authentication details
        // Configure session management, beneficial for scalable and secure RESTful APIs where each request is authenticated independently without relying on server-side session storage.
        // so session id won't show
        http.sessionManagement(session
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(withDefaults());       // this is form based authentication(default)
        http.httpBasic(withDefaults());     // this is pop up based authentication(basic authentication)
        // Allow the H2 console to be accessed within the same origin , all frames will be enabled
        http.headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        // Disable CSRF protection (be cautious with this in production)
        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }



    //in memory authentication as storing user details in the memory
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("password1"))            // here password will be encoded and saved to the database using BCrypt(contains salting) also
                .roles("USER")
                .build();

        UserDetails admin1 = User.withUsername("admin")
                .password(passwordEncoder().encode("adminPassword"))
                .roles("ADMIN")
                .build();

        // test using in memory data( no need for database), here these user1, admin1 account won't be created in database
        // InMemoryUserDetailsManager needs object of type 'UserDetails' as arguments
        // we can pass any number of objects as arguments
//        return new InMemoryUserDetailsManager(user1,admin1);



        // but here a new record will be created to the  H2 database using JdbcUserDetailsManager class
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user1);           // creating new user
        jdbcUserDetailsManager.createUser(admin1);
        return jdbcUserDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();     // in spring security BCrypt is commonly used
    }
}
