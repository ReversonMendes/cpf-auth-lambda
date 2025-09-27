package com.example.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminSetUserPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserCreationHandler implements RequestHandler<APIGatewayProxyRequestEvent, ApiGatewayResponse> {

    private static final CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    // Configuration loaded from environment variables
    private static final String USER_POOL_ID = System.getenv("COGNITO_USER_POOL_ID");
    private static final String APP_CLIENT_ID = System.getenv("COGNITO_APP_CLIENT_ID");

    private static final String FIXED_PASSWORD = "@Jpq9897gh";

    @Override
    public ApiGatewayResponse handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        try {
            if (USER_POOL_ID == null || USER_POOL_ID.trim().isEmpty()) {
                throw new IllegalStateException("Environment variable 'COGNITO_USER_POOL_ID' is not set.");
            }
            if (APP_CLIENT_ID == null || APP_CLIENT_ID.trim().isEmpty()) {
                throw new IllegalStateException("Environment variable 'COGNITO_APP_CLIENT_ID' is not set.");
            }

            // Use a dedicated request object for user creation
            UserCreationRequest creationRequest = objectMapper.readValue(input.getBody(), UserCreationRequest.class);
            String cpf = creationRequest.getCpf();

            // Basic validation
            if (cpf == null || cpf.trim().isEmpty()) {
                return ApiGatewayResponse.build(400, Map.of("error", "cpf is required."));
            }

            // Step 1: Create the user administratively
            AdminCreateUserRequest createUserRequest = AdminCreateUserRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(cpf)
                    // No attributes are being sent as email is removed.
                    // .userAttributes(...)
                    .messageAction("SUPPRESS") // Suppress the default welcome email with a temporary password
                    .build();

            cognitoClient.adminCreateUser(createUserRequest);
            context.getLogger().log("User created successfully with username: " + cpf);

            // Step 2: Set the password as permanent
            AdminSetUserPasswordRequest setPasswordRequest = AdminSetUserPasswordRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(cpf)
                    .password(FIXED_PASSWORD)
                    .permanent(true) // This is the key to avoid the temporary password flow
                    .build();

            cognitoClient.adminSetUserPassword(setPasswordRequest);
            context.getLogger().log("Permanent password set for user: " + cpf);

            // Step 3: Authenticate the new user to get tokens
            Map<String, String> authParameters = new HashMap<>();
            authParameters.put("USERNAME", cpf);
            authParameters.put("PASSWORD", FIXED_PASSWORD);

            InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(authParameters)
                    .clientId(APP_CLIENT_ID)
                    .build();

            InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);
            AuthenticationResultType authResult = authResponse.authenticationResult();

            if (authResult != null && authResult.idToken() != null) {
                Map<String, String> tokens = new HashMap<>();
                tokens.put("idToken", authResult.idToken());
                tokens.put("accessToken", authResult.accessToken());
                tokens.put("refreshToken", authResult.refreshToken());
                return ApiGatewayResponse.build(201, tokens);
            } else {
                return ApiGatewayResponse.build(500, Map.of("error", "User created, but failed to retrieve tokens."));
            }

        } catch (CognitoIdentityProviderException e) {
            context.getLogger().log("Cognito Error: " + e.awsErrorDetails().errorMessage());
            return ApiGatewayResponse.build(400, Map.of("error", e.awsErrorDetails().errorMessage()));
        } catch (Exception e) {
            context.getLogger().log("Internal Server Error: " + e.getMessage());
            return ApiGatewayResponse.build(500, Map.of("error", "An internal error occurred."));
        }
    }
}
