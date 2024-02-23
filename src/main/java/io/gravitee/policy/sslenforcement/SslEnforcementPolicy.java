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

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.util.Maps;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.sslenforcement.configuration.CertificateLocation;
import io.gravitee.policy.sslenforcement.configuration.SslEnforcementPolicyConfiguration;
import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.util.StringUtils;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
public class SslEnforcementPolicy {

    private final SslEnforcementPolicyConfiguration configuration;

    static final String SSL_REQUIRED = "SSL_ENFORCEMENT_SSL_REQUIRED";

    static final String AUTHENTICATION_REQUIRED = "SSL_ENFORCEMENT_AUTHENTICATION_REQUIRED";

    static final String CLIENT_FORBIDDEN = "SSL_ENFORCEMENT_CLIENT_FORBIDDEN";

    public SslEnforcementPolicy(SslEnforcementPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {
        SSLSession sslSession = request.sslSession();

        // No SSL at all, go to next policy
        if (!configuration.isRequiresSsl() && sslSession == null) {
            policyChain.doNext(request, response);

            return;
        }

        if (configuration.isRequiresSsl() && sslSession == null) {
            policyChain.failWith(
                PolicyResult.failure(SSL_REQUIRED, HttpStatusCode.FORBIDDEN_403, "Access to the resource requires SSL certificate.")
            );

            return;
        }

        var principal = extractX500Principal(request);
        if (configuration.isRequiresClientAuthentication() && principal == null) {
            policyChain.failWith(PolicyResult.failure(AUTHENTICATION_REQUIRED, HttpStatusCode.UNAUTHORIZED_401, "Unauthorized"));

            return;
        }

        if (
            configuration.isRequiresClientAuthentication() &&
            configuration.getWhitelistClientCertificates() != null &&
            !configuration.getWhitelistClientCertificates().isEmpty()
        ) {
            X500Name peerName = new X500Name(principal.getName());

            boolean found = false;

            for (String name : configuration.getWhitelistClientCertificates()) {
                // Prepare name with javax.security to transform to valid bouncycastle Asn1ObjectIdentifier
                final X500Principal x500Principal = new X500Principal(name);
                final X500Name x500Name = new X500Name(x500Principal.getName());
                found = X500NameComparator.areEqual(x500Name, peerName);

                if (found) {
                    break;
                }
            }

            if (!found) {
                policyChain.failWith(
                    PolicyResult.failure(
                        CLIENT_FORBIDDEN,
                        HttpStatusCode.FORBIDDEN_403,
                        "You're not allowed to access this resource",
                        Maps.<String, Object>builder().put("name", principal.getName()).build()
                    )
                );

                return;
            }
        }

        policyChain.doNext(request, response);
    }

    private X500Principal extractX500Principal(Request request) {
        if (configuration.getCertificateLocation() == CertificateLocation.SESSION) {
            SSLSession sslSession = request.sslSession();

            if (null != sslSession) {
                try {
                    return (X500Principal) sslSession.getPeerPrincipal();
                } catch (SSLPeerUnverifiedException e) {
                    return null;
                }
            }
            return null;
        }

        return extractCertificate(request.headers(), configuration.getCertificateHeaderName())
            .map(X509Certificate::getSubjectX500Principal)
            .orElse(null);
    }

    public static Optional<X509Certificate> extractCertificate(final HttpHeaders httpHeaders, final String certHeader) {
        Optional<X509Certificate> certificate = Optional.empty();

        String certHeaderValue = StringUtils.hasText(certHeader) ? httpHeaders.get(certHeader) : null;

        if (certHeaderValue != null) {
            try {
                if (!certHeaderValue.contains("\n")) {
                    certHeaderValue = URLDecoder.decode(certHeaderValue, Charset.defaultCharset());
                }
                certHeaderValue = certHeaderValue.replaceAll("\t", "\n");
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                certificate =
                    Optional.ofNullable(
                        (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certHeaderValue.getBytes()))
                    );
            } catch (Exception e) {
                log.debug("Unable to retrieve peer certificate from request header '{}'", certHeader, e);
            }
        } else {
            log.debug("Header '{}' missing, unable to retrieve client certificate", certHeader);
        }

        return certificate;
    }
}
