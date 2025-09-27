package com.example.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;

import java.util.Map;

/**
 * An example handler for a protected API endpoint.
 * This handler assumes that a Cognito Authorizer has already validated the JWT
 * and will pass the user's claims in the request context.
 */
public class ProfileHandler implements RequestHandler<APIGatewayProxyRequestEvent, ApiGatewayResponse> {

    @Override
    public ApiGatewayResponse handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        try {
            // 1. Access the claims passed by the Cognito Authorizer
            // The authorizer injects the token's claims into the request context.
            Map<String, Object> claims = input.getRequestContext().getAuthorizer().getClaims();

            // 2. Extract the user's unique identifier
            // The 'sub' (Subject) claim is the standard, unique, and immutable user ID from Cognito.
            // It's the best practice for identifying a user.
            String userId = (String) claims.get("sub");

            // You can also access any other claim present in your IdToken, like the CPF.
            // The claim name will be what you defined in Cognito (e.g., "cpf", "username", "email").
            String cpf = (String) claims.get("username"); // Assuming 'username' is the CPF

            if (userId == null || userId.trim().isEmpty()) {
                // This case is unlikely if the authorizer is set up correctly, but it's good practice to check.
                return ApiGatewayResponse.build(403, Map.of("error", "Forbidden: User identifier not found in token."));
            }

            context.getLogger().log("Request successfully authorized for user ID: " + userId);

            // 3. --- YOUR BUSINESS LOGIC GOES HERE ---
            // Now that you have the user's ID, you can securely fetch their profile
            // from a database (like DynamoDB), process an order, etc.

            // For this example, we'll just return the user's information.
            Map<String, String> userProfile = Map.of(
                "userId", userId,
                "cpf", cpf,
                "message", "Successfully accessed protected profile data."
            );

            return ApiGatewayResponse.build(200, userProfile);

        } catch (Exception e) {
            context.getLogger().log("Error processing protected request: " + e.getMessage());
            return ApiGatewayResponse.build(500, Map.of("error", "Internal server error while fetching profile."));
        }
    }
}
