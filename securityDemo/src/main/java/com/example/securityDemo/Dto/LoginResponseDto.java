package com.example.securityDemo.Dto;

import lombok.Data;

import java.util.List;

@Data
public class LoginResponseDto {
    private String jwtToken;
    private String userName;
    private List<String> roles;

    public LoginResponseDto(String userName,List<String> roles,String jwtToken){
        this.userName=userName;
        this.roles=roles;
        this.jwtToken=jwtToken;
    }
}
