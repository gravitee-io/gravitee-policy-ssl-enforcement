/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.sslenforcement;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.sslenforcement.configuration.SslEnforcementPolicyConfiguration;
import java.util.Collections;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import lombok.SneakyThrows;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SslEnforcementPolicyTest {

    @Mock
    private Request request;

    @Mock
    private SSLSession sslSession;

    @Mock
    private Response response;

    @Mock
    protected PolicyChain policyChain;

    @Captor
    protected ArgumentCaptor<PolicyResult> resultCaptor;

    @BeforeEach
    void init() {
        when(request.sslSession()).thenReturn(sslSession);
    }

    @Test
    void should_go_to_next_policy_when_require_ssl_is_disabled() {
        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(false).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @ParameterizedTest
    @ValueSource(
        strings = {
            "CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US",
            "C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke",
            "C=US, O=Sun Microsystems, CN=Duke, OU=JavaSoft",
        }
    )
    void should_go_to_next_policy_when_consumer_certificate_is_in_the_whitelist(String whitelist) throws SSLPeerUnverifiedException {
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));
        var configuration = SslEnforcementPolicyConfiguration
            .builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList(whitelist))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @ParameterizedTest
    @ValueSource(
        strings = {
            "CN=Duke,OU=JavaSoft,O=*,C=US",
            "CN=Duke, OU=JavaSoft, O=*, C=??",
            "C=US, O=*, OU=JavaSoft, CN=Duke",
            "C=??, O=*, OU=JavaSoft, CN=Duke",
        }
    )
    void should_go_to_next_policy_when_consumer_certificate_match_to_pattern_in_the_whitelist(String pattern)
        throws SSLPeerUnverifiedException {
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));
        var configuration = SslEnforcementPolicyConfiguration
            .builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList(pattern))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    void should_fail_when_require_ssl_is_enabled_but_no_session() {
        when(request.sslSession()).thenReturn(null);
        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.SSL_REQUIRED);
    }

    @Test
    @SneakyThrows
    void should_fail_when_require_client_authentication_is_enabled_but_no_certifcate() {
        when(sslSession.getPeerPrincipal()).thenReturn(null);
        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).requiresClientAuthentication(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.AUTHENTICATION_REQUIRED);
    }

    @Test
    @SneakyThrows
    void should_fail_when_the_consumer_certificate_does_not_match_with_the_whitelist() {
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=Unknown"));
        var configuration = SslEnforcementPolicyConfiguration
            .builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.CLIENT_FORBIDDEN);
    }
}
