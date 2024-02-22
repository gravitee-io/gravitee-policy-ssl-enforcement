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

import java.util.Map;
import lombok.Getter;

@Getter
public enum CertificateLocation {
    HEADER("header"),
    SESSION("sessions");

    private static final Map<String, CertificateLocation> LABELS_MAP = Map.of(HEADER.label, HEADER, SESSION.label, SESSION);

    private final String label;

    CertificateLocation(String label) {
        this.label = label;
    }

    public static CertificateLocation fromLabel(String label) {
        if (label != null) {
            return LABELS_MAP.get(label);
        }
        return null;
    }
}
