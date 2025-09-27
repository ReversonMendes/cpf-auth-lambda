package com.example.lambda;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.Map;

public class ApiGatewayResponse {
    private final int statusCode;
    private final String body;
    private final Map<String, String> headers;

    public ApiGatewayResponse(int statusCode, String body, Map<String, String> headers) {
        this.statusCode = statusCode;
        this.body = body;
        this.headers = headers;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getBody() {
        return body;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public static ApiGatewayResponse build(int statusCode, Object body) {
        ObjectMapper objectMapper = new ObjectMapper();
        String bodyString;
        try {
            bodyString = objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            return new ApiGatewayResponse(500, "Error serializing response body", Collections.singletonMap("Content-Type", "application/json"));
        }
        return new ApiGatewayResponse(statusCode, bodyString, Collections.singletonMap("Content-Type", "application/json"));
    }
}