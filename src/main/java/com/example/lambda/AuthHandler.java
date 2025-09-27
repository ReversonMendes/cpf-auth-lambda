package com.example.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.crypto.spec.SecretKeySpec;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuthHandler implements RequestHandler<APIGatewayProxyRequestEvent, ApiGatewayResponse> {

    private final String userPoolId = System.getenv("COGNITO_USER_POOL_ID");
    private final String jwtSecret = System.getenv("JWT_SECRET_KEY");
    private final String cognitoAttributeName = "cpf"; // O nome do atributo no Cognito

    private final CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public ApiGatewayResponse handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        context.getLogger().log("Received request body: " + input.getBody());

        try {
            AuthRequest authRequest = objectMapper.readValue(input.getBody(), AuthRequest.class);
            String cpf = authRequest.getCpf();

            if (cpf == null || cpf.trim().isEmpty()) {
                return ApiGatewayResponse.build(400, Map.of("error", "cpf field is required"));
            }

            // Query Cognito for users with the specified CPF attribute
            // Note: The filter does not use the "custom:" prefix.
            String filter = String.format("%s = \"%s\"", cognitoAttributeName, cpf);
            ListUsersRequest req = ListUsersRequest.builder()
                    .userPoolId(userPoolId)
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
            SecretKeySpec secretKeySpec = new SecretKeySpec(jwtSecret.getBytes(), SignatureAlgorithm.HS256.getJcaName());

            String jwt = Jwts.builder()
                    .setSubject(user.username())
                    .setIssuedAt(Date.from(now))
                    .setExpiration(Date.from(now.plusSeconds(3600))) // Expires in 1 hour
                    .claim("cpf", cpf)
                    .signWith(secretKeySpec)
                    .compact();

            return ApiGatewayResponse.build(200, Map.of("token", jwt));

        } catch (Exception e) {
            context.getLogger().log("Error processing request: " + e.getMessage());
            return ApiGatewayResponse.build(500, Map.of("error", "Internal server error"));
        }
    }
}
