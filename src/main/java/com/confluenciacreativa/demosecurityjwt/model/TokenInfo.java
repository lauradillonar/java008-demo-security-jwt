package com.confluenciacreativa.demosecurityjwt.model;

import java.io.Serializable;

public class TokenInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String jwttoken;

    public TokenInfo(String jwttoken) {
        this.jwttoken = jwttoken;
    }

    public String getToken() {
        return this.jwttoken;
    }
}