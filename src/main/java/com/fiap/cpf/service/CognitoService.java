package com.fiap.cpf.service;

import com.fiap.cpf.api.LoginResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.Map;

public class CognitoService {

    private final String userPoolId = System.getenv("USER_POOL_ID");
    private final String clientId = System.getenv("USER_POOL_CLIENT");
    private final CognitoIdentityProviderClient cognito = CognitoIdentityProviderClient.create();

    public LoginResponse loginWithCpf(String cpf) {
        // Inicia auth custom
        AdminInitiateAuthResponse authResponse = cognito.adminInitiateAuth(
                AdminInitiateAuthRequest.builder()
                        .authFlow(AuthFlowType.CUSTOM_AUTH)
                        .clientId(clientId)
                        .userPoolId(userPoolId)
                        .authParameters(Map.of("USERNAME", cpf))
                        .build()
        );

        AuthenticationResultType result = authResponse.authenticationResult();
        return new LoginResponse(
                result.accessToken(),
                result.idToken(),
                result.refreshToken()
        );
    }
}