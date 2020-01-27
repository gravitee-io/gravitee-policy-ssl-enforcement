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
package io.gravitee.policy.sslenforcement.configuration;

import io.gravitee.policy.api.PolicyConfiguration;

import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class SslEnforcementPolicyConfiguration implements PolicyConfiguration {

    private boolean requiresSsl;

    private boolean requiresClientAuthentication;

    // Whitelist client certificates
    private List<String> whitelistClientCertificates;

    public List<String> getWhitelistClientCertificates() {
        return whitelistClientCertificates;
    }

    public void setWhitelistClientCertificates(List<String> whitelistClientCertificates) {
        this.whitelistClientCertificates = whitelistClientCertificates;
    }

    public boolean isRequiresSsl() {
        return requiresSsl;
    }

    public void setRequiresSsl(boolean requiresSsl) {
        this.requiresSsl = requiresSsl;
    }

    public boolean isRequiresClientAuthentication() {
        return requiresClientAuthentication;
    }

    public void setRequiresClientAuthentication(boolean requiresClientAuthentication) {
        this.requiresClientAuthentication = requiresClientAuthentication;
    }
}
