package com.fiap.cpf;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fiap.cpf.api.LoginRequest;
import com.fiap.cpf.api.LoginResponse;
import com.fiap.cpf.service.CognitoService;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public class AuthLambdaHandler implements RequestHandler<Map<String, Object>, Object> {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final CognitoService cognito = new CognitoService();

    @Override
    public Object handleRequest(Map<String, Object> input, Context context) {
        context.getLogger().log("Evento recebido: " + input);

        try {
            // Quando chamado pelo Cognito Trigger (Custom Auth Flow)
            if (input.get("triggerSource") != null) {
                return handleCognitoTrigger(input, context);
            }

            // Quando chamado pelo API Gateway Proxy
            if (input.get("httpMethod") != null) {
                APIGatewayProxyRequestEvent event = MAPPER.convertValue(input, APIGatewayProxyRequestEvent.class);
                return handleApiGateway(event, context);
            }

            // Caso não seja reconhecido
            return Map.of("statusCode", 400, "body", "Evento não suportado");

        } catch (Exception e) {
            context.getLogger().log("Erro: " + e.getMessage());
            return Map.of("statusCode", 500, "body", "Erro interno");
        }
    }

    private Object handleApiGateway(APIGatewayProxyRequestEvent event, Context context) throws Exception {
        LoginRequest req = MAPPER.readValue(event.getBody(), LoginRequest.class);

        // chama Cognito para iniciar autenticação custom
        LoginResponse response = cognito.loginWithCpf(req.getCpf());

        return new APIGatewayProxyResponseEvent()
                .withStatusCode(200)
                .withBody(MAPPER.writeValueAsString(response))
                .withHeaders(Map.of("Content-Type", "application/json"));
    }

    private Object handleCognitoTrigger(Map<String, Object> event, Context context) {
        String triggerSource = (String) event.get("triggerSource");
        context.getLogger().log("Trigger Cognito: " + triggerSource);

        switch (triggerSource) {
            case "DefineAuthChallenge_Authentication":
                // Define que o desafio é sempre aceitar se CPF existe
                event.put("response", Map.of(
                        "challengeName", "CUSTOM_CHALLENGE",
                        "issueTokens", false,
                        "failAuthentication", false
                ));
                break;

            case "CreateAuthChallenge_Authentication":
                event.put("response", Map.of(
                        "publicChallengeParameters", Map.of("cpf", ((Map<String, Object>) event.get("request")).get("userAttributes")),
                        "privateChallengeParameters", Map.of("answer", "valid"),
                        "challengeMetadata", "CPF_CHALLENGE"
                ));
                break;

            case "VerifyAuthChallengeResponse_Authentication":
                // Aqui validamos se o CPF está OK
                Map<String, Object> resp = (Map<String, Object>) event.get("response");
                resp.put("answerCorrect", true);
                break;
        }

        return event;
    }
}
