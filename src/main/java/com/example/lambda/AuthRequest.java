package com.example.lambda;

// This class is a Data Transfer Object (DTO) for the login request.
public class AuthRequest {
    private String cpf;
    private String password;

    // Getters and Setters
    public String getCpf() {
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}