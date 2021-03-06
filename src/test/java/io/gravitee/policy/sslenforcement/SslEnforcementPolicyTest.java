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

import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.sslenforcement.configuration.SslEnforcementPolicyConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class SslEnforcementPolicyTest {

    private SslEnforcementPolicy policy;

    @Mock
    private SslEnforcementPolicyConfiguration configuration;

    @Mock
    private Request request;

    @Mock
    private SSLSession sslSession;

    @Mock
    private Response response;

    @Mock
    protected PolicyChain policyChain;

    @Before
    public void init() {
        initMocks(this);

        when(request.sslSession()).thenReturn(sslSession);

        policy = new SslEnforcementPolicy(configuration);
    }

    @Test
    public void shouldGoToNextPolicy() {
        policy.onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    public void shouldFail_requiresSsl_withoutSession() {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(request.sslSession()).thenReturn(null);

        policy.onRequest(request, response, policyChain);

        verify(policyChain).failWith(argThat(result -> SslEnforcementPolicy.SSL_REQUIRED.equals(result.key())));
    }

    @Test
    public void shouldFail_requiresClientAuthentication_withoutSession() {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(configuration.isRequiresClientAuthentication()).thenReturn(true);

        policy.onRequest(request, response, policyChain);

        verify(policyChain).failWith(argThat(result -> SslEnforcementPolicy.AUTHENTICATION_REQUIRED.equals(result.key())));
    }

    @Test
    public void shouldFail_whitelistClientCertificate_unknownClient() throws SSLPeerUnverifiedException {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(configuration.isRequiresClientAuthentication()).thenReturn(true);
        when(configuration.getWhitelistClientCertificates()).thenReturn(Collections.singletonList("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=Unknown"));

        policy.onRequest(request, response, policyChain);

        verify(policyChain).failWith(argThat(result -> SslEnforcementPolicy.CLIENT_FORBIDDEN.equals(result.key())));
    }

    @Test
    public void shouldFail_whitelistClientCertificate_validClient() throws SSLPeerUnverifiedException {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(configuration.isRequiresClientAuthentication()).thenReturn(true);
        when(configuration.getWhitelistClientCertificates()).thenReturn(Collections.singletonList("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));

        policy.onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    public void shouldFail_whitelistClientCertificate_validClient_pattern() throws SSLPeerUnverifiedException {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(configuration.isRequiresClientAuthentication()).thenReturn(true);
        when(configuration.getWhitelistClientCertificates()).thenReturn(Collections.singletonList("CN=Duke,OU=JavaSoft,O=*,C=US"));
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));

        policy.onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    public void shouldFail_whitelistClientCertificate_validClient_pattern2() throws SSLPeerUnverifiedException {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(configuration.isRequiresClientAuthentication()).thenReturn(true);
        when(configuration.getWhitelistClientCertificates()).thenReturn(Collections.singletonList("CN=Duke,OU=JavaSoft,O=*,C=??"));
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));

        policy.onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    public void shouldFail_whitelistClientCertificate_reorder() throws SSLPeerUnverifiedException {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(configuration.isRequiresClientAuthentication()).thenReturn(true);
        when(configuration.getWhitelistClientCertificates()).thenReturn(Collections.singletonList("C=FR, O=GraviteeSource, CN=localhost"));
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=localhost,O=GraviteeSource,C=FR"));

        policy.onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    public void shouldFail_whitelistClientCertificate_reorder_pattern() throws SSLPeerUnverifiedException {
        when(configuration.isRequiresSsl()).thenReturn(true);
        when(configuration.isRequiresClientAuthentication()).thenReturn(true);
        when(configuration.getWhitelistClientCertificates()).thenReturn(Collections.singletonList("C=FR, O=*, CN=localhost"));
        when(sslSession.getPeerPrincipal()).thenReturn(new X500Principal("CN=localhost,O=GraviteeSource,C=FR"));

        policy.onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }
}
