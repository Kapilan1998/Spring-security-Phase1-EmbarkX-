package com.example.securityDemo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
/**
 * The AuthEntryPointJwt class handles unauthorized access attempts by implementing the AuthenticationEntryPoint interface. When an unauthorized request is made, the commence method:
 *
 *     Logs details about the authentication exception.
 *     Sets the response content type to JSON and the status to 401 Unauthorized.
 *     Constructs a JSON response body with details about the error, including status, error message, and the path of the request.
 *     Writes the JSON response body to the output stream, which is sent back to the client.
 * **/
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.info("authException details "+ authException);
        log.info("Unauthorized error "+ authException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);  //response body will be in JSON format.
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);    //Sets the HTTP status code of the response to 401 Unauthorized

        final Map<String,Object> body = new HashMap<>();
        body.put("status",HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error","Unauthorized");
        body.put("message",authException.getMessage());
        body.put("path",request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();
        //Writes the body map as a JSON object to the response's output stream, thereby sending the JSON response to the client.
        mapper.writeValue(response.getOutputStream(),body);

    }
}
