package com.example.lambda;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthRequest {
    private final String cpf;

    @JsonCreator
    public AuthRequest(@JsonProperty("cpf") String cpf) {
        this.cpf = cpf;
    }

    public String getCpf() { return cpf; }
}