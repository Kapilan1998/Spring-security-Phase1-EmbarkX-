package com.example.securityDemo.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

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
}
