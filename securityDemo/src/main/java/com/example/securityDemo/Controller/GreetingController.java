package com.example.securityDemo.Controller;

import com.example.securityDemo.Dto.LoginRequestDto;
import com.example.securityDemo.Dto.LoginResponseDto;
import com.example.securityDemo.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
public class GreetingController {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @GetMapping("/sayHello")
    public String sayHello() {
        return "Hello";
    }

    // here only the roles having USER can able to access this end points, others can't
    @PreAuthorize("hasRole('USER')")        // to limit the user access(authorization)
    @GetMapping("/viewAsUser")
    public String enterAsUser() {
        return "Hello User !!!";
    }

    // here only the roles having ADMIN can able to access this end points, others can't
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/viewAsAdmin")
    public String enterAsAdmin() {
        return "Hello Admin !!!";
    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequestDto loginRequestDto){
        Authentication authentication;
        try {
            //to authenticate the user with the username and password by creating a UsernamePasswordAuthenticationToken.
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.getUserName(),loginRequestDto.getPassword()));
        }catch (AuthenticationException exception){
            Map<String,Object> map = new HashMap<>();
            map.put("message","Invalid credentials");
                    map.put("status",false);
                    return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        //essential for Spring Security to recognize the authenticated user in subsequent requests.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtils.generateTokenFromUserName(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item->item.getAuthority())
                .collect(Collectors.toList());

        LoginResponseDto response = new LoginResponseDto(userDetails.getUsername(),roles,jwtToken);
        return ResponseEntity.ok(response);
    }
}
