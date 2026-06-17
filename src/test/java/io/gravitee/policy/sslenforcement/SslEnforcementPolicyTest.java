/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.sslenforcement;

import static java.util.Objects.requireNonNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.sslenforcement.configuration.CertificateLocation;
import io.gravitee.policy.sslenforcement.configuration.SslEnforcementPolicyConfiguration;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import lombok.SneakyThrows;
import org.assertj.core.api.Assertions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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
        lenient().when(request.sslSession()).thenReturn(sslSession);
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
    void should_go_to_next_policy_when_consumer_certificate_in_session_is_in_the_whitelist(String whitelist)
        throws SSLPeerUnverifiedException {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder()
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
    void should_go_to_next_policy_when_consumer_certificate_in_session_match_to_pattern_in_the_whitelist(String pattern)
        throws SSLPeerUnverifiedException {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList(pattern))
            .build();

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
    @SneakyThrows
    void should_go_to_next_policy_when_consumer_certificate_in_header_is_in_the_whitelist(String whitelist) {
        var certs = loadCertificate();
        HttpHeaders headers = HttpHeaders.create().set("ssl-client-cert", certs);
        when(request.headers()).thenReturn(headers);

        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList(whitelist))
            .certificateLocation(CertificateLocation.HEADER)
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
    void should_go_to_next_policy_when_requires_ssl_and_trust_x_forwarded_proto_and_header_https() {
        when(request.sslSession()).thenReturn(null);
        HttpHeaders headers = HttpHeaders.create().set("X-Forwarded-Proto", "https");
        when(request.headers()).thenReturn(headers);

        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).useXForwardedProto(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    void should_fail_when_requires_ssl_and_trust_x_forwarded_proto_but_proto_is_http() {
        when(request.sslSession()).thenReturn(null);
        HttpHeaders headers = HttpHeaders.create().set("X-Forwarded-Proto", "http");
        when(request.headers()).thenReturn(headers);

        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).useXForwardedProto(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.SSL_REQUIRED);
    }

    @Test
    void should_fail_when_requires_ssl_and_x_forwarded_proto_https_but_trust_disabled() {
        when(request.sslSession()).thenReturn(null);
        // When useXForwardedProto is false, policy does not read headers; no need to stub headers.

        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).useXForwardedProto(false).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.SSL_REQUIRED);
    }

    @Test
    void should_go_to_next_policy_when_trust_x_forwarded_proto_and_forwarded_header_proto_https() {
        when(request.sslSession()).thenReturn(null);
        HttpHeaders headers = HttpHeaders.create().set("Forwarded", "proto=https");
        when(request.headers()).thenReturn(headers);

        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).useXForwardedProto(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_fail_when_require_client_authentication_is_enabled_but_no_certifcate() {
        when(sslSession.getPeerCertificates()).thenThrow(new SSLPeerUnverifiedException("peer not verified"));
        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).requiresClientAuthentication(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.AUTHENTICATION_REQUIRED);
    }

    @Test
    @SneakyThrows
    void should_fail_when_the_consumer_certificate_does_not_match_with_the_whitelist() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=Unknown"));
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.CLIENT_FORBIDDEN);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_session_peer_certificate_subject_matches_whitelist() {
        X509Certificate cert = loadX509Certificate();
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });

        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_fail_when_certificate_lacks_required_policy_oid() {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .requiredCertificatePolicies(Collections.singletonList("0.4.0.19495.1.3"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.OID_MISMATCH);
    }

    @Test
    @SneakyThrows
    void should_fail_when_certificate_policy_oids_do_not_include_required_oid() {
        X509Certificate cert = buildCertWithPolicyOids("1.2.3.4");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .requiredCertificatePolicies(Collections.singletonList("0.4.0.19495.1.3"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.OID_MISMATCH);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_certificate_contains_required_policy_oid() {
        X509Certificate cert = buildCertWithPolicyOids("0.4.0.19495.1.3");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .requiredCertificatePolicies(Collections.singletonList("0.4.0.19495.1.3"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_fail_when_certificate_contains_only_some_of_multiple_required_policy_oids() {
        X509Certificate cert = buildCertWithPolicyOids("0.4.0.19495.1.3");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .requiredCertificatePolicies(java.util.List.of("0.4.0.19495.1.3", "1.2.3.4"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.OID_MISMATCH);
    }

    @Test
    @SneakyThrows
    void should_fail_with_oid_mismatch_when_certificate_policies_extension_is_malformed() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getExtensionValue("2.5.29.32")).thenReturn(new byte[] { 0x42, 0x42, 0x42 });
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .requiredCertificatePolicies(Collections.singletonList("0.4.0.19495.1.3"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.OID_MISMATCH);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_certificate_san_matches_whitelist_ant_pattern() {
        X509Certificate cert = buildCertWithSan("api.example.com");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("*.example.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_any_one_of_multiple_san_values_matches_whitelist() {
        X509Certificate cert = buildCertWithSan("api.other.com", "api.allowed.com", "api.third.com");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("api.allowed.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_san_matches_whitelist_case_insensitively() {
        // Per RFC 5280 / 6125, DNS and email SAN values are case-insensitive.
        // A cert with SAN "API.Example.com" must match whitelist "api.example.com".
        X509Certificate cert = buildCertWithSan("API.Example.com");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("api.example.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_certificate_san_matches_whitelist_literal() {
        X509Certificate cert = buildCertWithSan("api.allowed.com");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("api.allowed.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_fail_when_certificate_san_values_do_not_match_whitelist() {
        X509Certificate cert = buildCertWithSan("api.other.com");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("api.allowed.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.SAN_MISMATCH);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_whitelist_subject_alternative_names_is_not_configured() {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).requiresClientAuthentication(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_whitelist_subject_alternative_names_is_empty() {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.emptyList())
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_non_dns_san_type_matches_whitelist() {
        // GeneralName type 1 = rfc822Name (email). Verifies the policy matches against
        // SAN values regardless of the type integer (ticket AC: "All SAN types matched").
        X509Certificate cert = mock(X509Certificate.class);
        Collection<List<?>> sans = List.of(Arrays.asList(1, "partner@allowed.com"));
        when(cert.getSubjectAlternativeNames()).thenReturn(sans);
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("partner@allowed.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_fail_with_san_mismatch_when_get_subject_alternative_names_throws() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectAlternativeNames()).thenThrow(new RuntimeException("malformed extension"));
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("api.example.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.SAN_MISMATCH);
    }

    @Test
    @SneakyThrows
    void should_fail_when_certificate_has_no_subject_alternative_names() {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistSubjectAlternativeNames(Collections.singletonList("api.example.com"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).failWith(resultCaptor.capture());
        Assertions.assertThat(resultCaptor.getValue().key()).isEqualTo(SslEnforcementPolicy.SAN_MISMATCH);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_required_certificate_policies_is_not_configured() {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder().requiresSsl(true).requiresClientAuthentication(true).build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_required_certificate_policies_is_empty() {
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { loadX509Certificate() });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .requiredCertificatePolicies(Collections.emptyList())
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @Test
    @SneakyThrows
    void should_go_to_next_policy_when_certificate_contains_all_multiple_required_policy_oids() {
        X509Certificate cert = buildCertWithPolicyOids("0.4.0.19495.1.3", "1.2.3.4");
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[] { cert });
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .requiredCertificatePolicies(java.util.List.of("0.4.0.19495.1.3", "1.2.3.4"))
            .build();

        new SslEnforcementPolicy(configuration).onRequest(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

    @SneakyThrows
    private static X509Certificate buildCertWithPolicyOids(String... oids) {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name issuer = new X500Name("CN=Test");
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        PolicyInformation[] policies = Arrays.stream(oids)
            .map(oid -> new PolicyInformation(new ASN1ObjectIdentifier(oid)))
            .toArray(PolicyInformation[]::new);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            issuer,
            keyPair.getPublic()
        );
        builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(policies));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @SneakyThrows
    private String loadCertificate() {
        var cert = Files.readString(Path.of(requireNonNull(this.getClass().getResource("/cert.pem")).toURI()));
        return URLEncoder.encode(cert, Charset.defaultCharset());
    }

    @SneakyThrows
    private X509Certificate loadX509Certificate() {
        try (InputStream is = requireNonNull(this.getClass().getResourceAsStream("/cert.pem"))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
    }

    @SneakyThrows
    private static X509Certificate buildCertWithSan(String... dnsNames) {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name issuer = new X500Name("CN=Test");
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        GeneralName[] names = Arrays.stream(dnsNames)
            .map(n -> new GeneralName(GeneralName.dNSName, n))
            .toArray(GeneralName[]::new);
        GeneralNames sans = new GeneralNames(names);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            issuer,
            keyPair.getPublic()
        );
        builder.addExtension(Extension.subjectAlternativeName, false, sans);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    void should_fail_fast_at_construction_when_a_whitelist_dn_is_malformed() {
        // DN whitelist is pre-parsed in the constructor, so a malformed entry surfaces at deploy
        // time rather than throwing on every request.
        var configuration = SslEnforcementPolicyConfiguration.builder()
            .requiresSsl(true)
            .requiresClientAuthentication(true)
            .whitelistClientCertificates(Collections.singletonList("this is not a valid distinguished name"))
            .build();

        Assertions.assertThatThrownBy(() -> new SslEnforcementPolicy(configuration)).isInstanceOf(IllegalArgumentException.class);
    }
}
