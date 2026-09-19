package com.hendisantika.springbootoauth2demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;

@SpringBootTest
@AutoConfigureMockMvc
class SpringBootOauth2DemoApplicationTests {

    @Autowired
    private MockMvcTester mvc;

    @Test
    void contextLoads() {
        assertThat(mvc).isNotNull();
    }

    @Test
    void protectedResourceRejectsAnonymousCallers() {
        assertThat(mvc.get().uri("/resources/user")).hasStatus(401);
    }

    @Test
    void userCanReachTheUserResource() {
        assertThat(mvc.get().uri("/resources/user").with(httpBasic("user", "password")))
                .hasStatus2xxSuccessful()
                .hasBodyTextEqualTo("hello user");
    }

    @Test
    void userCannotReachTheAdminResource() {
        assertThat(mvc.get().uri("/resources/admin").with(httpBasic("user", "password")))
                .hasStatus(403);
    }

    @Test
    void adminCanReachTheAdminResource() {
        assertThat(mvc.get().uri("/resources/admin").with(httpBasic("admin", "password")))
                .hasStatus2xxSuccessful()
                .hasBodyTextEqualTo("hello admin");
    }

    @Test
    void badCredentialsAreRejected() {
        assertThat(mvc.get().uri("/resources/user").with(httpBasic("user", "wrong")))
                .hasStatus(401);
    }

    @Test
    void jwksEndpointIsPubliclyReadable() {
        assertThat(mvc.get().uri("/oauth2/jwks"))
                .hasStatus2xxSuccessful()
                .bodyText().contains("\"kty\":\"RSA\"");
    }
}
