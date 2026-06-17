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
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
public class SslEnforcementPolicy {

    private final SslEnforcementPolicyConfiguration configuration;

    /**
     * DN whitelist pre-parsed into BouncyCastle {@link X500Name} objects at construction time.
     * Policy instances are created once per API deployment, so parsing here keeps the per-request
     * path allocation-free instead of re-parsing every configured DN on each call.
     */
    private final List<X500Name> whitelistClientCertificateNames;

    static final String SSL_REQUIRED = "SSL_ENFORCEMENT_SSL_REQUIRED";

    static final String AUTHENTICATION_REQUIRED = "SSL_ENFORCEMENT_AUTHENTICATION_REQUIRED";

    static final String CLIENT_FORBIDDEN = "SSL_ENFORCEMENT_CLIENT_FORBIDDEN";

    static final String OID_MISMATCH = "SSL_ENFORCEMENT_OID_MISMATCH";

    static final String SAN_MISMATCH = "SSL_ENFORCEMENT_SAN_MISMATCH";

    private static final String CERTIFICATE_POLICIES_OID = "2.5.29.32";

    // DNS and email SAN values are case-insensitive per RFC 5280 / 6125.
    private static final AntPathMatcher SAN_MATCHER;

    static {
        SAN_MATCHER = new AntPathMatcher();
        SAN_MATCHER.setCaseSensitive(false);
    }

    public SslEnforcementPolicy(SslEnforcementPolicyConfiguration configuration) {
        this.configuration = configuration;
        this.whitelistClientCertificateNames = parseWhitelistClientCertificates(configuration.getWhitelistClientCertificates());
    }

    private static List<X500Name> parseWhitelistClientCertificates(List<String> whitelist) {
        if (CollectionUtils.isEmpty(whitelist)) {
            return List.of();
        }
        List<X500Name> names = new ArrayList<>(whitelist.size());
        for (String name : whitelist) {
            // Normalize through javax.security so BouncyCastle gets canonical ASN.1 object identifiers.
            names.add(new X500Name(new X500Principal(name).getName()));
        }
        return names;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {
        boolean secure = isSecure(request);

        // No SSL at all, go to next policy
        if (!configuration.isRequiresSsl() && !secure) {
            policyChain.doNext(request, response);
            return;
        }

        if (configuration.isRequiresSsl() && !secure) {
            policyChain.failWith(
                PolicyResult.failure(SSL_REQUIRED, HttpStatusCode.FORBIDDEN_403, "Access to the resource requires SSL certificate.")
            );
            return;
        }

        var certificate = extractCertificate(request).orElse(null);
        if (configuration.isRequiresClientAuthentication() && certificate == null) {
            policyChain.failWith(PolicyResult.failure(AUTHENTICATION_REQUIRED, HttpStatusCode.UNAUTHORIZED_401, "Unauthorized"));
            return;
        }

        if (!enforceDnWhitelist(certificate, policyChain)) return;
        if (!enforceRequiredOids(certificate, policyChain)) return;
        if (!enforceSanWhitelist(certificate, policyChain)) return;

        policyChain.doNext(request, response);
    }

    private boolean enforceDnWhitelist(X509Certificate certificate, PolicyChain policyChain) {
        if (!configuration.isRequiresClientAuthentication() || whitelistClientCertificateNames.isEmpty()) {
            return true;
        }
        X500Principal principal = certificate.getSubjectX500Principal();
        X500Name peerName = new X500Name(principal.getName());

        for (X500Name x500Name : whitelistClientCertificateNames) {
            if (X500NameComparator.areEqual(x500Name, peerName)) {
                return true;
            }
        }

        policyChain.failWith(
            PolicyResult.failure(
                CLIENT_FORBIDDEN,
                HttpStatusCode.FORBIDDEN_403,
                "You're not allowed to access this resource",
                Maps.<String, Object>builder().put("name", principal.getName()).build()
            )
        );
        return false;
    }

    private boolean enforceRequiredOids(X509Certificate certificate, PolicyChain policyChain) {
        if (!shouldEnforce(configuration.getRequiredCertificatePolicies())) {
            return true;
        }
        Set<String> presentOids = extractCertificatePolicyOids(certificate);
        if (presentOids.containsAll(configuration.getRequiredCertificatePolicies())) {
            return true;
        }
        policyChain.failWith(
            PolicyResult.failure(
                OID_MISMATCH,
                HttpStatusCode.FORBIDDEN_403,
                "Certificate does not contain required policy OIDs",
                Maps.<String, Object>builder().put("required", configuration.getRequiredCertificatePolicies()).build()
            )
        );
        return false;
    }

    private boolean enforceSanWhitelist(X509Certificate certificate, PolicyChain policyChain) {
        if (!shouldEnforce(configuration.getWhitelistSubjectAlternativeNames())) {
            return true;
        }
        Collection<List<?>> sans;
        try {
            sans = certificate.getSubjectAlternativeNames();
        } catch (Exception e) {
            log.debug("Unable to read subject alternative names from certificate", e);
            sans = null;
        }
        if (sans != null && !sans.isEmpty() && anySanMatchesWhitelist(sans, configuration.getWhitelistSubjectAlternativeNames())) {
            return true;
        }
        policyChain.failWith(
            PolicyResult.failure(
                SAN_MISMATCH,
                HttpStatusCode.FORBIDDEN_403,
                "Certificate does not match required Subject Alternative Names",
                Maps.<String, Object>builder().put("whitelist", configuration.getWhitelistSubjectAlternativeNames()).build()
            )
        );
        return false;
    }

    private boolean isSecure(Request request) {
        if (request.sslSession() != null) {
            return true;
        }
        if (configuration.isUseXForwardedProto()) {
            return forwardedProtoIsHttps(request.headers());
        }
        return false;
    }

    private boolean forwardedProtoIsHttps(HttpHeaders headers) {
        if (headers == null) {
            return false;
        }
        String xForwardedProto = headers.get("X-Forwarded-Proto");
        if (xForwardedProto != null && "https".equalsIgnoreCase(xForwardedProto.trim())) {
            return true;
        }
        String forwarded = headers.get("Forwarded");
        if (forwarded != null && forwarded.toLowerCase().contains("proto=https")) {
            return true;
        }
        return false;
    }

    private Optional<X509Certificate> extractCertificate(Request request) {
        if (configuration.getCertificateLocation() == CertificateLocation.SESSION) {
            SSLSession sslSession = request.sslSession();
            if (sslSession == null) {
                return Optional.empty();
            }
            try {
                Certificate[] peerCertificates = sslSession.getPeerCertificates();
                if (peerCertificates != null && peerCertificates.length > 0 && peerCertificates[0] instanceof X509Certificate x509) {
                    return Optional.of(x509);
                }
                return Optional.empty();
            } catch (SSLPeerUnverifiedException e) {
                return Optional.empty();
            }
        }

        return extractCertificate(request.headers(), configuration.getCertificateHeaderName());
    }

    private boolean shouldEnforce(Collection<?> whitelist) {
        return configuration.isRequiresClientAuthentication() && !CollectionUtils.isEmpty(whitelist);
    }

    private static boolean anySanMatchesWhitelist(Collection<List<?>> sans, List<String> whitelist) {
        for (List<?> san : sans) {
            if (san.size() < 2) {
                continue;
            }
            Object value = san.get(1);
            if (value instanceof String sanValue) {
                for (String pattern : whitelist) {
                    if (SAN_MATCHER.match(pattern, sanValue)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Set<String> extractCertificatePolicyOids(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(CERTIFICATE_POLICIES_OID);
        if (extensionValue == null) {
            return Set.of();
        }
        try {
            ASN1OctetString octetString = (ASN1OctetString) ASN1Primitive.fromByteArray(extensionValue);
            CertificatePolicies policies = CertificatePolicies.getInstance(ASN1Primitive.fromByteArray(octetString.getOctets()));
            Set<String> oids = new HashSet<>();
            for (PolicyInformation pi : policies.getPolicyInformation()) {
                oids.add(pi.getPolicyIdentifier().getId());
            }
            return oids;
        } catch (Exception e) {
            log.debug("Unable to parse certificatePolicies extension", e);
            return Set.of();
        }
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
                certificate = Optional.ofNullable(
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
