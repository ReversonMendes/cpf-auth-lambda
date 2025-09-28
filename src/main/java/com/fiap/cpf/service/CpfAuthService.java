package com.fiap.cpf.service;

import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

public class CpfAuthService {
    private final CognitoIdentityProviderClient cognito;
    private final String userPoolId;

    public CpfAuthService(String userPoolId) {
        this.cognito = CognitoIdentityProviderClient.create();
        this.userPoolId = userPoolId;
    }

    public void ensureUserExists(String cpf) {
        try {
            cognito.adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cpf)
                    .build());
        } catch (UserNotFoundException e) {
            // Usuário não existe → cria
            cognito.adminCreateUser(AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cpf)
                    .userAttributes(
                            AttributeType.builder().name("custom:cpf").value(cpf).build(),
                            AttributeType.builder().name("email_verified").value("true").build()
                    )
                    .messageAction("SUPPRESS")
                    .build());


            // Define uma senha aleatória (não será usada, mas precisa)
            String randomPassword = java.util.UUID.randomUUID().toString() + "Ab1!";

            cognito.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cpf)
                    .password(randomPassword)
                    .permanent(true) // senha definitiva, sem obrigar alteração
                    .build());

            // Confirma o usuário (opcional, geralmente já confirmado com permanent password)
            cognito.adminConfirmSignUp(AdminConfirmSignUpRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cpf)
                    .build());
        }
    }
}
