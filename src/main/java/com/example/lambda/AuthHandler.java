package com.example.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

public class AuthHandler implements RequestHandler<APIGatewayProxyRequestEvent, ApiGatewayResponse> {

    // Best Practice: Initialize heavyweight, thread-safe objects once.
    private static final CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    // Configuration is loaded once per cold start
    private static final String USER_POOL_ID = System.getenv("COGNITO_USER_POOL_ID");
    private static final String APP_CLIENT_ID = System.getenv("COGNITO_APP_CLIENT_ID");

    @Override
    public ApiGatewayResponse handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        context.getLogger().log("Received request body: " + input.getBody());

        try {
            // Best Practice: Fail-fast by validating configuration at the start.
            if (USER_POOL_ID == null || USER_POOL_ID.trim().isEmpty()) {
                throw new IllegalStateException("Environment variable 'COGNITO_USER_POOL_ID' is not set.");
            }
            if (APP_CLIENT_ID == null || APP_CLIENT_ID.trim().isEmpty()) {
                throw new IllegalStateException("Environment variable 'COGNITO_APP_CLIENT_ID' is not set.");
            }

            String requestBody = input.getBody();
            if (requestBody == null || requestBody.trim().isEmpty()) {
                return ApiGatewayResponse.build(400, Map.of("error", "Request body is missing or empty"));
            }

            AuthRequest authRequest = objectMapper.readValue(requestBody, AuthRequest.class);
            String cpf = authRequest.getCpf();
            String password = authRequest.getPassword();

            // More robust validation for input
            if (cpf == null || cpf.trim().isEmpty() || password == null || password.trim().isEmpty()) {
                return ApiGatewayResponse.build(400, Map.of("error", "cpf and password fields are required"));
            }

            // Use USER_PASSWORD_AUTH flow to authenticate the user with Cognito
            Map<String, String> authParameters = new HashMap<>();
            authParameters.put("USERNAME", cpf);
            authParameters.put("PASSWORD", password);

            InitiateAuthRequest authRequestCognito = InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(authParameters)
                    .clientId(APP_CLIENT_ID)
                    .build();

            InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequestCognito);
            AuthenticationResultType authResult = authResponse.authenticationResult();

            if (authResult != null && authResult.idToken() != null) {
                // Return the tokens provided by Cognito
                Map<String, String> tokens = Map.of(
                        "idToken", authResult.idToken(),
                        "accessToken", authResult.accessToken(),
                        "refreshToken", authResult.refreshToken()
                );
                return ApiGatewayResponse.build(200, tokens);
            } else {
                // Should not happen in a normal flow, but good to handle
                return ApiGatewayResponse.build(500, Map.of("error", "Cognito did not return a valid token"));
            }
        } catch (JsonProcessingException e) {
            return ApiGatewayResponse.build(400, Map.of("error", "Invalid request body format"));
        } catch (NotAuthorizedException | UserNotFoundException e) {
            return ApiGatewayResponse.build(401, Map.of("error", "Invalid credentials"));
        } catch (Exception e) {
            // Log the full exception for better debugging
            context.getLogger().log("Error processing request: " + e);
            return ApiGatewayResponse.build(500, Map.of("error", "Internal server error"));
        }
    }
}
