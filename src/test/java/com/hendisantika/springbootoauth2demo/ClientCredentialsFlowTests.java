package com.hendisantika.springbootoauth2demo;

import com.jayway.jsonpath.JsonPath;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end check of the client_credentials grant: fetch a token from the authorization
 * server, then spend it on a resource guarded by the role that token carries.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ClientCredentialsFlowTests {

    @Autowired
    private MockMvcTester mvc;

    @Test
    void trustedClientExchangesItsSecretForAUsableToken() throws Exception {
        String accessToken = fetchAccessToken("trusted-app", "secret");

        assertThat(mvc.get().uri("/resources/trusted_client").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .hasStatus2xxSuccessful()
                .hasBodyTextEqualTo("hello user authenticated by trusted client");
    }

    @Test
    void tokenFromTheTrustedClientDoesNotUnlockOtherRoles() throws Exception {
        String accessToken = fetchAccessToken("trusted-app", "secret");

        assertThat(mvc.get().uri("/resources/admin").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .hasStatus(403);
    }

    @Test
    void tokenCarriesOnlyTheClientsOwnRole() throws Exception {
        String accessToken = fetchAccessToken("trusted-app", "secret");

        // There is no end user behind a client_credentials token, so no user role may leak in.
        assertThat(claimsOf(accessToken)).extractingByKey("roles")
                .asInstanceOf(InstanceOfAssertFactories.list(String.class))
                .containsExactly("TRUSTED_CLIENT");
        assertThat(claimsOf(accessToken)).containsEntry("aud", "spring-boot-application");
    }

    @Test
    void wrongClientSecretIsRejected() {
        assertThat(mvc.post().uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic("trusted-app", "not-the-secret"))
                .param("grant_type", "client_credentials"))
                .hasStatus(401);
    }

    private String fetchAccessToken(String clientId, String clientSecret) throws Exception {
        String body = mvc.post().uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(clientId, clientSecret))
                .param("grant_type", "client_credentials")
                .param("scope", "read write")
                .exchange()
                .getResponse()
                .getContentAsString();

        String accessToken = JsonPath.read(body, "$.access_token");
        assertThat(accessToken).as("token response was %s", body).isNotBlank();
        return accessToken;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> claimsOf(String accessToken) {
        String payload = accessToken.split("\\.")[1];
        String json = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        return JsonPath.parse(json).json();
    }

    private static String basic(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}
