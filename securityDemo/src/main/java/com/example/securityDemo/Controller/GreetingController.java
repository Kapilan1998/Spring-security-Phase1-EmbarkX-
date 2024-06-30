package com.example.securityDemo.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @GetMapping("/sayHello")
    public String sayHello() {
        return "Hello";
    }

}
