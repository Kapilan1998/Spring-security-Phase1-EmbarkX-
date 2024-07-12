package com.example.securityDemo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
/**
 * AuthTokenFilter class extends OncePerRequestFilter to ensure it is applied once per request.
 * Autowires JwtUtils and UserDetailsService to handle JWT operations and user details retrieval.
 * doFilterInternal method extracts and validates the JWT, retrieves user details, and sets the authentication context if the JWT is valid.
 * parseJwt method extracts the JWT from the request header.
 * Logging is used extensively for debugging and tracking the flow of the filter's operations.
 *
 * This class ensures that each request is checked for a valid JWT token, and if valid,
 * sets the appropriate authentication context for the request, enabling secure access control in the application.
 *
 *
 * **/
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    UserDetailsService userDetailsService;      // used to retrieve user details from a username

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        log.info("AuthTokenFilter called for URI " + request.getRequestURI());
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String userName = jwtUtils.getUserNameFromJwtToken(jwt);
                        //Loads the user details for the extracted username using userDetailsService.
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                //Creates an UsernamePasswordAuthenticationToken object using the retrieved user details and authorities.
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                log.info("Roles from JWT  " + userDetails.getAuthorities());

                // Sets additional details on the authentication token using the current request.
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

//                Sets the authentication in the security context, indicating the user is authenticated.
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (Exception e) {
            log.info("exception is " + e);
        }
        // Continues the filter chain, allowing the request to proceed.
        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        log.info("jwt " + jwt);
        return jwt;
    }
}
