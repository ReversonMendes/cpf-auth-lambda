package com.fiap.cpf;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fiap.cpf.api.LoginRequest;
import com.fiap.cpf.api.LoginResponse;
import com.fiap.cpf.service.CognitoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fiap.cpf.service.ConfigService;
import com.fiap.cpf.service.UserService;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AuthLambdaHandler implements RequestHandler<Map<String, Object>, Object> {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final CognitoService cognito = new CognitoService();
    private final UserService userService = new UserService(ConfigService.getUserPoolId());

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
                APIGatewayProxyRequestEvent request = MAPPER.convertValue(input, APIGatewayProxyRequestEvent.class);

                String path = request.getPath();
                String method = request.getHttpMethod();

                if ("/login".equals(path) && "POST".equalsIgnoreCase(method)) {
                    return createUser(request, context);
                } else if ("/login".equals(path) && "GET".equalsIgnoreCase(method)) {
                    return authenticateUser(request, context);
                } else {
                    return resposta(404, "Rota não encontrada");
                }
            }

            // Caso não seja reconhecido
            return Map.of("statusCode", 400, "body", "Evento não suportado");

        } catch (Exception e) {
            context.getLogger().log("Erro: " + e.getMessage());
            return resposta(500, e.getMessage());
        }
    }

    private APIGatewayProxyResponseEvent createUser(APIGatewayProxyRequestEvent input, Context context) throws JsonProcessingException {
        LoginRequest req = MAPPER.readValue(input.getBody(), LoginRequest.class);
        context.getLogger().log("CPF recebido: " + req.getCpf());

        userService.ensureUserExists(req.getCpf());
        return resposta(201, "Usuário criado com sucesso");
    }

    private APIGatewayProxyResponseEvent authenticateUser(APIGatewayProxyRequestEvent request, Context context) throws JsonProcessingException {
        LoginRequest req = MAPPER.readValue(request.getBody(), LoginRequest.class);
        context.getLogger().log("CPF recebido: " + req.getCpf());

        if (req.getCpf() == null) {
            return new APIGatewayProxyResponseEvent().withStatusCode(400).withBody("CPF obrigatório");
        }
        String cpf = request.getQueryStringParameters().get("cpf");

        //chama Cognito para iniciar autenticação custom
        LoginResponse response = cognito.loginWithCpf(req.getCpf());

        logger.log(Level.INFO, response.toString());

        return resposta(200, MAPPER.writeValueAsString(response));
    }

//    @Override
//    public Object handleRequest(Map<String, Object> input, Context context) {
//        context.getLogger().log("Evento recebido: " + input);
//
//        try {
//            // Quando chamado pelo Cognito Trigger (Custom Auth Flow)
//            if (input.get("triggerSource") != null) {
//                return handleCognitoTrigger(input, context);
//            }
//
//            // Quando chamado pelo API Gateway Proxy
//            if (input.get("requestContext") != null && ((Map<String, Object>) input.get("requestContext")).get("http") != null) {
//                APIGatewayProxyRequestEvent event = MAPPER.convertValue(input, APIGatewayProxyRequestEvent.class);
//                return handleApiGatewayLogin(event, context);
//            }
//
//            // Caso não seja reconhecido
//            return Map.of("statusCode", 400, "body", "Evento não suportado");
//
//        } catch (Exception e) {
//            context.getLogger().log("Erro: " + e.getMessage());
//            return Map.of("statusCode", 500, "body", "Erro interno");
//        }
//    }


//    private APIGatewayProxyResponseEvent handleApiGatewayLogin(APIGatewayProxyRequestEvent input, Context context) {
//        try {
//
//            LoginRequest req = MAPPER.readValue(input.getBody(), LoginRequest.class);
//            context.getLogger().log("CPF recebido: " + req.getCpf());
//
//            if (req.getCpf() == null) {
//                return new APIGatewayProxyResponseEvent().withStatusCode(400).withBody("CPF obrigatório");
//            }
//
//            String cpf = req.getCpf();
//
//            // ======= 1. Valida no banco interno =======
//            boolean cpfValidoNoBanco = validarCpfNoBanco(cpf);
//            if (!cpfValidoNoBanco) {
//                return new APIGatewayProxyResponseEvent().withStatusCode(401).withBody("Usuário não encontrado");
//            }
//
//            // ======= 2. Garantir que usuário exista no Cognito =======
//            boolean isUserCriado = userService.ensureUserExists(cpf);
//            if (!isUserCriado) {
//                return new APIGatewayProxyResponseEvent().withStatusCode(201).withBody("Usuário criado. Por favor, tente o login novamente.");
//            }
//
//
//            //chama Cognito para iniciar autenticação custom
//            LoginResponse response = cognito.loginWithCpf(req.getCpf());
//
//            logger.log(Level.INFO, response.toString());
//
//            return new APIGatewayProxyResponseEvent()
//                    .withStatusCode(200)
//                    .withBody(response != null
//                            ? MAPPER.writeValueAsString(response)
//                            : "Desafio enviado (aguardando resposta)");
//
//        } catch (Exception e) {
//            context.getLogger().log("Erro: " + e.getMessage());
//            return new APIGatewayProxyResponseEvent().withStatusCode(500).withBody("Erro interno");
//        }
//    }

    private Object handleCognitoTrigger(Map<String, Object> event, Context context) {
        String triggerSource = (String) event.get("triggerSource");
        context.getLogger().log("Trigger Cognito: " + triggerSource);

        logger.log(Level.INFO, "Trigger Cognito: " + triggerSource);
        switch (triggerSource) {
            case "DefineAuthChallenge_Authentication":
                logger.log(Level.INFO, "#1 DefineAuthChallenge_Authentication");
                handleDefineAuthChallenge(event);
                break;

            case "CreateAuthChallenge_Authentication":
                logger.log(Level.INFO, "#2 CreateAuthChallenge_Authentication");
                handleCreateAuthChallenge(event);
                break;

            case "VerifyAuthChallengeResponse_Authentication":
                logger.log(Level.INFO, "#3 VerifyAuthChallengeResponse_Authentication");
                handleVerifyAuthChallenge(event);
                break;

            default:
                context.getLogger().log("Trigger inesperado: " + triggerSource);
        }
        return event;
    }

    // DefineAuthChallenge -> diz se ainda precisa validar ou se já está autenticado
    private void handleDefineAuthChallenge(Map<String, Object> event) {

        Map<String, Object> response = getResponseMap(event);

        response.put("issueTokens", true);
        response.put("failAuthentication", false);

        logger.log(Level.INFO, "Fluxo custom: login autorizado automaticamente.");
    }

    // CreateAuthChallenge -> Como é só CPF, apenas "marca" que o fluxo é verdadeiro
    private void handleCreateAuthChallenge(Map<String, Object> event) {
        logger.log(Level.INFO, "CreateAuthChallenge ignorado (fluxo sempre verdadeiro).");
    }

    // VerifyAuthChallengeResponse
    private void handleVerifyAuthChallenge(Map<String, Object> event) {
        Map<String, Object> response = getResponseMap(event);
        response.put("answerCorrect", true); // sempre verdadeiro
        logger.log(Level.INFO, "VerifyAuthChallenge sempre verdadeiro.");

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

    private APIGatewayProxyResponseEvent resposta(int status, String body) {
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(status)
                .withBody(body)
                .withHeaders(Map.of("Content-Type", "application/json"));
    }
}
