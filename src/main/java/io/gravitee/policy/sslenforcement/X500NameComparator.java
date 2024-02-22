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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.springframework.util.AntPathMatcher;

public class X500NameComparator {

    private X500NameComparator() {}

    public static boolean areEqual(X500Name name1, X500Name name2) {
        final RDN[] rdns1 = name1.getRDNs();
        final RDN[] rdns2 = name2.getRDNs();

        if (rdns1.length != rdns2.length) {
            return false;
        }

        boolean reverse = false;

        if (rdns1[0].getFirst() != null && rdns2[0].getFirst() != null) {
            reverse = !rdns1[0].getFirst().getType().equals(rdns2[0].getFirst().getType()); // guess forward
        }

        for (int i = 0; i != rdns1.length; i++) {
            if (!foundMatch(reverse, rdns1[i], rdns2)) {
                return false;
            }
        }

        return true;
    }

    private static boolean foundMatch(boolean reverse, RDN rdn, RDN[] possRDNs) {
        if (reverse) {
            for (int i = possRDNs.length - 1; i >= 0; i--) {
                if (possRDNs[i] != null && rDNAreEqual(rdn, possRDNs[i])) {
                    possRDNs[i] = null;
                    return true;
                }
            }
        } else {
            for (int i = 0; i != possRDNs.length; i++) {
                if (possRDNs[i] != null && rDNAreEqual(rdn, possRDNs[i])) {
                    possRDNs[i] = null;
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean rDNAreEqual(RDN rdn1, RDN rdn2) {
        if (rdn1.isMultiValued()) {
            if (rdn2.isMultiValued()) {
                AttributeTypeAndValue[] atvs1 = rdn1.getTypesAndValues();
                AttributeTypeAndValue[] atvs2 = rdn2.getTypesAndValues();

                if (atvs1.length != atvs2.length) {
                    return false;
                }

                for (int i = 0; i != atvs1.length; i++) {
                    if (!atvAreEqual(atvs1[i], atvs2[i])) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        } else {
            if (!rdn2.isMultiValued()) {
                return atvAreEqual(rdn1.getFirst(), rdn2.getFirst());
            } else {
                return false;
            }
        }

        return true;
    }

    private static boolean atvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2) {
        if (atv1 == atv2) {
            return true;
        }

        if (atv1 == null) {
            return false;
        }

        if (atv2 == null) {
            return false;
        }

        ASN1ObjectIdentifier o1 = atv1.getType();
        ASN1ObjectIdentifier o2 = atv2.getType();

        if (!o1.equals(o2)) {
            return false;
        }

        String v1 = IETFUtils.canonicalize(IETFUtils.valueToString(atv1.getValue()));
        String v2 = IETFUtils.canonicalize(IETFUtils.valueToString(atv2.getValue()));

        AntPathMatcher matcher = new AntPathMatcher();

        return matcher.match(v1, v2);
    }
}
