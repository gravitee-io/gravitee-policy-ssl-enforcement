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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SslEnforcementPolicyConfiguration implements PolicyConfiguration {

    @Builder.Default
    private boolean requiresSsl = true;

    private boolean requiresClientAuthentication;

    /** Allowed client certificates (requires client authentication) **/
    private List<String> whitelistClientCertificates;

    @Builder.Default
    private CertificateLocation certificateLocation = CertificateLocation.SESSION;

    /** Name of the header where to find the client certificate when using header certificate location **/
    @Builder.Default
    private String certificateHeaderName = "ssl-client-cert";
}
