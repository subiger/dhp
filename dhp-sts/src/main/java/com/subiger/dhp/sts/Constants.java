/*
 * Copyright 2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.subiger.dhp.sts;

/**
 * @author Renaud Subiger
 * @since 1.0.0
 */
public class Constants {

    // Namespaces

    public static final String TRC_NS_URI = "http://epsos.eu/trc";

    public static final String WS_TRUST_SERVICE_NS_URI = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/wsdl";

    // TRC Parameters

    public static final String DISPENSATION_PIN_CODE = "urn:ehdsi:names:document:document-id:dispensationPinCode";

    public static final String PRESCRIPTION_ID = "urn:ehdsi:names:document:document-id:prescriptionId";

    public static final String PURPOSE_OF_USE = "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse";

    public static final String SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

    private Constants() {
    }
}
