package com.fiap.cpf;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fiap.cpf.api.LoginRequest;
import com.fiap.cpf.api.LoginResponse;
import com.fiap.cpf.service.CognitoService;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AuthLambdaHandler implements RequestHandler<Map<String, Object>, Object> {


    // No início da classe
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private final CognitoService cognito = new CognitoService();
    private final Logger logger = Logger.getLogger(AuthLambdaHandler.class.getName());


    @Override
    public Object handleRequest(Map<String, Object> input, Context context) {
        context.getLogger().log("Evento recebido: " + input);

        try {
            // Quando chamado pelo Cognito Trigger (Custom Auth Flow)
            if (input.get("triggerSource") != null) {
                return handleCognitoTrigger(input, context);
            }

            // Quando chamado pelo API Gateway Proxy
            if (input.get("requestContext") != null && ((Map<String, Object>) input.get("requestContext")).get("http") != null) {
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

        logger.log(Level.INFO, "Trigger Cognito: " + triggerSource);
        switch (triggerSource) {
            case "DefineAuthChallenge_Authentication":
                return handleDefineAuthChallenge(event);

            case "CreateAuthChallenge_Authentication":
                return handleCreateAuthChallenge(event);

            case "VerifyAuthChallengeResponse_Authentication":
                return handleVerifyAuthChallenge(event);

            default:
                context.getLogger().log("Trigger inesperado: " + triggerSource);
                return event;
        }
    }

    // DefineAuthChallenge -> diz se ainda precisa validar ou se já está autenticado
    private Map<String, Object> handleDefineAuthChallenge(Map<String, Object> event) {
        Map<String, Object> response = getResponseMap(event);

        logger.log(Level.INFO, response.toString());

        // Se o CPF já foi validado, autentica
        Boolean cpfValidado = (Boolean) ((Map<String, Object>) event.get("request"))
                .getOrDefault("cpfValido", false);

        if (cpfValidado) {
            logger.log(Level.INFO, "CPF já foi validado");
            response.put("challengeName", null);
            response.put("issueTokens", true);
            response.put("failAuthentication", false);
        } else {
            logger.log(Level.INFO, "CPF ainda não foi validado");
            response.put("challengeName", "CUSTOM_CHALLENGE");
            response.put("issueTokens", false);
            response.put("failAuthentication", false);
        }

        return response;
    }

    // CreateAuthChallenge -> aqui você poderia gerar código, SMS etc.
    // Como é só CPF, apenas "marca" que o desafio foi criado
    private Map<String, Object> handleCreateAuthChallenge(Map<String, Object> event) {
        Map<String, Object> response = getResponseMap(event);

        Map<String, Object> challengeMetaData = new HashMap<>();
        challengeMetaData.put("info", "Validação de CPF requerida");

        response.put("publicChallengeParameters", challengeMetaData);
        response.put("privateChallengeParameters", challengeMetaData);
        response.put("challengeMetadata", "CPF_VALIDATION");
        logger.log(Level.INFO, "CPF ainda não foi validado");

        return response;
    }

    // VerifyAuthChallengeResponse -> onde validamos o CPF no banco
    private Map<String, Object> handleVerifyAuthChallenge(Map<String, Object> event) {
        Map<String, Object> response = getResponseMap(event);

        Map<String, Object> userAnswer = (Map<String, Object>) ((Map<String, Object>) event.get("request")).get("challengeAnswer");
        String cpfInformado = (String) userAnswer.get("cpf");

        // TODO: aqui você valida no banco se o CPF existe
        logger.log(Level.INFO, "Validando CPF: " + cpfInformado);
        boolean valido = validarCpfNoBanco(cpfInformado);

        if (valido) {
            logger.log(Level.INFO, "CPF " + cpfInformado + " validado com sucesso.");
            response.put("answerCorrect", true);
            // marca que o CPF já foi validado, para o DefineAuthChallenge usar
            ((Map<String, Object>) event.get("request")).put("cpfValido", true);
        } else {
            response.put("answerCorrect", false);
            logger.log(Level.WARNING, "CPF " + cpfInformado + " inválido.");
        }

        return response;
    }

    // Função fake para simular consulta no banco
    private boolean validarCpfNoBanco(String cpf) {
        // Exemplo: só aceita CPF "12345678900"
        return "12345678900".equals(cpf);
    }

    private Map<String, Object> getResponseMap(Map<String, Object> event) {
        if (!event.containsKey("response")) {
            event.put("response", new HashMap<String, Object>());
        }
        return (Map<String, Object>) event.get("response");
    }
}
