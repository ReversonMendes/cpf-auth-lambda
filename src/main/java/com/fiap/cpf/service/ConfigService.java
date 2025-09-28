package com.fiap.cpf.service;

import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;

public class ConfigService {

    private static final String PARAM_USER_POOL = System.getenv("SSM_PATH_USER_POOL");
    private static final String PARAM_CLIENT_ID = System.getenv("SSM_PATH_CLIENT_ID");

    private static final SsmClient ssm = SsmClient.create();

    public static String getUserPoolId() {
        return getParam(PARAM_USER_POOL);
    }

    public static String getClientId() {
        return getParam(PARAM_CLIENT_ID);
    }

    private static String getParam(String name) {
        return ssm.getParameter(GetParameterRequest.builder()
                        .name(name)
                        .withDecryption(true)
                        .build())
                .parameter()
                .value();
    }
}
