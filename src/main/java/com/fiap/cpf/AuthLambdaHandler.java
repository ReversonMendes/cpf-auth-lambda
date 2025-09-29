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
import com.fiap.cpf.service.ConfigService;
import com.fiap.cpf.service.UserService;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.ssm.SsmClient;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AuthLambdaHandler implements RequestHandler<Map<String, Object>, Object> {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final CognitoService cognitoService = new CognitoService();
    private final CognitoIdentityProviderClient cognito;

    public AuthLambdaHandler() {
        cognito = CognitoIdentityProviderClient.create();
    }

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
                APIGatewayProxyRequestEvent event = MAPPER.convertValue(input, APIGatewayProxyRequestEvent.class);
                return handleApiGatewayLogin(event, context);
            }

            // Caso não seja reconhecido
            return Map.of("statusCode", 400, "body", "Evento não suportado");

        } catch (Exception e) {
            context.getLogger().log("Erro: " + e.getMessage());
            return Map.of("statusCode", 500, "body", "Erro interno");
        }
    }


    private APIGatewayProxyResponseEvent handleApiGatewayLogin(APIGatewayProxyRequestEvent input, Context context) {
        try {

            LoginRequest req = MAPPER.readValue(input.getBody(), LoginRequest.class);
            context.getLogger().log("CPF recebido: " + req.getCpf());

            if (req.getCpf() == null) {
                return new APIGatewayProxyResponseEvent().withStatusCode(400).withBody("CPF obrigatório");
            }

            String cpf = req.getCpf();

            // ======= 1. Valida no banco interno =======
            boolean cpfValidoNoBanco = validarCpfNoBanco(cpf);
            if (!cpfValidoNoBanco) {
                return new APIGatewayProxyResponseEvent().withStatusCode(401).withBody("Usuário não encontrado");
            }


            userService.ensureUserExists(cpf);

            //chama Cognito para iniciar autenticação custom
            LoginResponse response = cognitoService.loginWithCpf(req.getCpf());

            logger.log(Level.INFO, response.toString());
          
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(200)
                .withBody(response != null ? MAPPER.writeValueAsString(response) : "Desafio enviado (aguardando resposta)")
                .withHeaders(Map.of("Content-Type", "application/json"));



        } catch (Exception e) {
            context.getLogger().log("Erro: " + e.getMessage());
            return new APIGatewayProxyResponseEvent().withStatusCode(500).withBody("Erro interno");
        }
    }


    private void ensureUserConfirmed(String cpf, Context context) {
        try {
            cognito.adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(ConfigService.getUserPoolId())
                    .username(cpf)
                    .build());
            // Usuário já existe e está confirmado
        } catch (UserNotFoundException e) {
            context.getLogger().log("Usuário não encontrado no User Pool. Criando...");

            // Cria usuário com email e email_verified
            cognito.adminCreateUser(AdminCreateUserRequest.builder()
                    .userPoolId(ConfigService.getUserPoolId())
                    .username(cpf)
                    .userAttributes(
                            AttributeType.builder().name("custom:cpf").value(cpf).build(),
                            AttributeType.builder().name("email").value(cpf + "@exemplo.com").build(),
                            AttributeType.builder().name("email_verified").value("true").build()
                    )
                    .messageAction("SUPPRESS")
                    .build());

            // Define senha permanente
            String randomPassword = UUID.randomUUID().toString() + "Ab1!";
            cognito.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
                    .userPoolId(ConfigService.getUserPoolId())
                    .username(cpf)
                    .password(randomPassword)
                    .permanent(true)
                    .build());

            // Confirma usuário
            cognito.adminConfirmSignUp(AdminConfirmSignUpRequest.builder()
                    .userPoolId(ConfigService.getUserPoolId())
                    .username(cpf)
                    .build());
        }
    }


//    private Object handleApiGateway(APIGatewayProxyRequestEvent event, Context context) throws Exception {
//        LoginRequest req = MAPPER.readValue(event.getBody(), LoginRequest.class);
//        context.getLogger().log("CPF recebido: " + req.getCpf());
//
//
//        // chama Cognito para iniciar autenticação custom
//        LoginResponse response = cognito.loginWithCpf(req.getCpf());
//
//        logger.log(Level.INFO, response.toString());
//
//        return new APIGatewayProxyResponseEvent()
//                .withStatusCode(200)
//                .withBody(MAPPER.writeValueAsString(response))
//                .withHeaders(Map.of("Content-Type", "application/json"));
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
        Boolean cpfValidado = (Boolean) ((Map<String, Object>) event.get("request")).getOrDefault("cpfValido", false);


        logger.log(Level.INFO, "CPFVALIDADO ? " + cpfValidado);
        if (cpfValidado != null && cpfValidado) {
            response.put("issueTokens", true);
            response.put("failAuthentication", false);
        } else {
            response.put("challengeName", "CUSTOM_CHALLENGE");
            response.put("issueTokens", false);
            response.put("failAuthentication", false);
        }

    }

    // CreateAuthChallenge -> Como é só CPF, apenas "marca" que o desafio foi criado
    private void handleCreateAuthChallenge(Map<String, Object> event) {
        Map<String, Object> response = getResponseMap(event);

        Map<String, Object> challengeMetaData = new HashMap<>();
        challengeMetaData.put("info", "Validação de CPF requerida");

        response.put("publicChallengeParameters", challengeMetaData);
        response.put("privateChallengeParameters", challengeMetaData);
        response.put("challengeMetadata", "CPF_VALIDATION");

        logger.log(Level.INFO, "CPF ainda não foi validado");
    }

    // VerifyAuthChallengeResponse
    private void handleVerifyAuthChallenge(Map<String, Object> event) {
        Map<String, Object> response = getResponseMap(event);

        Map<String, Object> userAnswer = (Map<String, Object>) ((Map<String, Object>) event.get("request")).get("challengeAnswer");
        String cpfInformado = (String) userAnswer.get("cpf");

        logger.log(Level.INFO, "CPF " + cpfInformado + " validado com sucesso.");
        
        response.put("answerCorrect", true);
        // marca que o CPF já foi validado, para o DefineAuthChallenge usar
        ((Map<String, Object>) event.get("request")).put("cpfValido", true);

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
