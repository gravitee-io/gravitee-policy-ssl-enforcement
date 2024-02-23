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

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.json.validation.InvalidJsonException;
import io.gravitee.json.validation.JsonSchemaValidator;
import io.gravitee.json.validation.JsonSchemaValidatorImpl;
import java.nio.file.Files;
import java.nio.file.Path;
import lombok.SneakyThrows;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SslEnforcementPolicyConfigurationTest {

    final JsonSchemaValidator jsonSchemaValidator = new JsonSchemaValidatorImpl();

    final String schema = loadResource("/schemas/schema-form.json");

    @Test
    @DisplayName("Should use default values when configuration is empty")
    void shouldSetDefaultValues() {
        String validated = jsonSchemaValidator.validate(schema, "{}");

        JSONObject defaultConfig = new JSONObject();
        defaultConfig.put("requiresSsl", true);
        defaultConfig.put("requiresClientAuthentication", false);
        defaultConfig.put("certificateLocation", "SESSION");
        defaultConfig.put("certificateHeaderName", "ssl-client-cert");

        assertThat(validated).isEqualTo(defaultConfig.toString());
    }

    @Test
    @DisplayName("Should validate client certificates against the pattern")
    void shouldValidateClientCertificates() {
        JSONArray distinguishedNames = new JSONArray();
        distinguishedNames.put("CN=client1");
        distinguishedNames.put("CN=Ben Gray,OU=editing,O=New York Times,C=US");
        distinguishedNames.put("CN=localhost,O=GraviteeSource*,C=??");
        distinguishedNames.put("C=FR, O=GUILDE DE L\\u2019APPLICATION, OU=0122 114570018, CN=gio-dev-batch-1.zsi.guilde");
        distinguishedNames.put("CN=Gio France, OU=0112 43370241179, O=Gio France, C=FR");
        distinguishedNames.put("CN=gio-calibration-api.gio.fr");
        distinguishedNames.put("CN=ers.gio.fr, OU=Direction, OU=0002 47939822400044, OU=GRAVITEE, O=GRAVITEE, L=LILLE, C=FR");
        distinguishedNames.put("C=FR, O=GUILDE DE L’APPLICATION, OU=0122 114570018, CN=gio-dev-batch-1.zsi.guilde");
        distinguishedNames.put("CN=test.flow, OU=0002 1232325234, O=SERVICE-PUBLIC GOUV, C=FR");
        distinguishedNames.put(
            "SERIALNUMBER=0001, CN=test.gio.fr, L=LILLE, 2.1.4.7=TREQS-45487, OU=Direction,OU=1202 848, OU=GIO, O=GIO, C=FR"
        );
        distinguishedNames.put("SERIALNUMBER=S23474, CN=test.gio.fr, L=LILLE, O=GIO, C=FR");
        distinguishedNames.put("CN=test.ers-gio.com, O=SAT , L=RAMONVILLE-SAINT-AGNE, S=Haute-Garonne, C=FR");

        String config = new JSONObject().put("whitelistClientCertificates", distinguishedNames).toString();

        String validated = jsonSchemaValidator.validate(schema, config);

        assertThat(validated).isNotBlank();
    }

    @Test
    @DisplayName("Should throw with invalid distinguished names")
    void shouldThrowWithInvalidDistinguishedNames() {
        JSONArray distinguishedNames = new JSONArray();
        distinguishedNames.put("An invalid input");

        String config = new JSONObject().put("whitelistClientCertificates", distinguishedNames).toString();

        Assertions.assertThrows(InvalidJsonException.class, () -> jsonSchemaValidator.validate(schema, config));
    }

    @SneakyThrows
    private String loadResource(String resource) {
        return Files.readString(Path.of(requireNonNull(this.getClass().getResource(resource)).toURI()));
    }
}
