package com.example.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.crypto.spec.SecretKeySpec;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class AuthHandler implements RequestHandler<APIGatewayProxyRequestEvent, ApiGatewayResponse> {

    // Best Practice: Initialize heavyweight, thread-safe objects once.
    private static final CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String cognitoAttributeName = "cpf"; // The attribute name in Cognito

    // Configuration is loaded once per cold start
    private static final String USER_POOL_ID = System.getenv("COGNITO_USER_POOL_ID");
    private static final String JWT_SECRET = System.getenv("JWT_SECRET_KEY");

    @Override
    public ApiGatewayResponse handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        context.getLogger().log("Received request body: " + input.getBody());

        try {
            // Best Practice: Fail-fast by validating configuration at the start.
            if (USER_POOL_ID == null || USER_POOL_ID.trim().isEmpty()) {
                throw new IllegalStateException("Environment variable 'COGNITO_USER_POOL_ID' is not set.");
            }
            if (JWT_SECRET == null || JWT_SECRET.trim().isEmpty()) {
                throw new IllegalStateException("Environment variable 'JWT_SECRET_KEY' is not set.");
            }

            String requestBody = input.getBody();
            if (requestBody == null || requestBody.trim().isEmpty()) {
                return ApiGatewayResponse.build(400, Map.of("error", "Request body is missing or empty"));
            }

            AuthRequest authRequest = objectMapper.readValue(requestBody, AuthRequest.class);
            String cpf = authRequest.getCpf();

            // More robust validation for CPF format
            if (cpf == null || !cpf.matches("\\d{11}")) {
                return ApiGatewayResponse.build(400, Map.of("error", "cpf field is required and must contain exactly 11 digits"));
            }

            // Query Cognito for users with the specified CPF attribute
            // Note: The filter does not use the "custom:" prefix.
            String filter = String.format("%s = \"%s\"", cognitoAttributeName, cpf);
            ListUsersRequest req = ListUsersRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .filter(filter)
                    .limit(1) // We only need to find one user
                    .build();

            ListUsersResponse listResp = cognitoClient.listUsers(req);
            List<UserType> users = listResp.users();

            if (users == null || users.isEmpty()) {
                return ApiGatewayResponse.build(404, Map.of("error", "user not found"));
            }

            UserType user = users.get(0);

            // Build JWT
            Instant now = Instant.now();
            SecretKeySpec secretKeySpec = new SecretKeySpec(JWT_SECRET.getBytes(), SignatureAlgorithm.HS256.getJcaName());

            String jwt = Jwts.builder()
                    .setSubject(user.username())
                    .setIssuedAt(Date.from(now))
                    .setExpiration(Date.from(now.plusSeconds(3600))) // Expires in 1 hour
                    .claim("cpf", cpf)
                    .signWith(secretKeySpec)
                    .compact();

            return ApiGatewayResponse.build(200, Map.of("token", jwt));

        } catch (Exception e) {
            // Log the full exception for better debugging
            context.getLogger().log("Error processing request: " + e);
            return ApiGatewayResponse.build(500, Map.of("error", "Internal server error"));
        }
    }
}
