package com.sm.controller.request;

import lombok.Data;

@Data
public class LoginDto {

    private String username;
    private String password;

    public void setUsername(String username) {
        this.username = username != null ? username.toLowerCase() : username;
    }

}
