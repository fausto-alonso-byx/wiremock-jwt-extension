package org.wiremock.extension.jwt;

import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseTransformerV2;
import com.github.tomakehurst.wiremock.http.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

public class JwtBodySigningTransformer implements ResponseTransformerV2 {

    private final JwtSigningKeySettings keySettings;


    // 🔧 Construtor usado em testes ou extensões personalizadas
    public JwtBodySigningTransformer(JwtSigningKeySettings keySettings) {
        this.keySettings = keySettings;
    }

    @Override
    public String getName() {
        return "jwt-body-signer";
    }

    @Override
    public Response transform(Response response, ServeEvent serveEvent) {
        System.out.println("JwtBodySigningTransformer transform");

        String originalBody = response.getBodyAsString();

        String token = encode(originalBody, keySettings.getRs256Algorithm());

        String signedBody = String.format("{\"encoded_body\": \"%s\"}", token);

        return Response.Builder.like(response)
                .but()
                .body(signedBody)
                .build();
    }


    public static String encode(String payloadJson, Algorithm algorithm) {
        // Cabeçalho fixo para RS256
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

        String headerB64 = base64urlEncode(headerJson);
        String payloadB64 = base64urlEncode(payloadJson);

        String headerDotPayload = headerB64 + "." + payloadB64;

        byte[] signatureBytes = algorithm.sign(headerDotPayload.getBytes(StandardCharsets.UTF_8));
        String signatureB64 = base64urlEncode(signatureBytes);

        return headerDotPayload + "." + signatureB64;
    }

    private static String base64urlEncode(String input) {
        return base64urlEncode(input.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64urlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
