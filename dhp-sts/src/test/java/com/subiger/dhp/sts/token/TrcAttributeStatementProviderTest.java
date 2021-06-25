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

package com.subiger.dhp.sts.token;

import com.subiger.dhp.sts.Constants;
import org.apache.cxf.jaxws.context.WrappedMessageContext;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.request.KeyRequirements;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.common.util.DOM2Writer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.Collections;
import java.util.Properties;

/**
 * @author Renaud Subiger
 * @since 1.0.0
 */
class TrcAttributeStatementProviderTest {

    private static final String PATIENT_ID = "2-1234-W4^^^&amp;2.16.17.710.850.1000.990.1&amp;ISO";
    private static final String PURPOSE_OF_USE = "EMERGENCY";
    private static final String PRESCRIPTION_ID = "PID-123456";
    private static final String DISPENSATION_PIN_CODE = "DPC-123456";

    @Test
    void testTrcAssertion() throws Exception {
        var tokenProvider = new SAMLTokenProvider();
        tokenProvider.setAttributeStatementProviders(Collections.singletonList(new TrcAttributeStatementProvider()));

        var providerParameters = createProviderParameters();
        var tokenRequirements = providerParameters.getTokenRequirements();

        Element trcParameters = createTrcParameters(
                // @formatter:off
                "<trc:TRCParameters xmlns:trc='http://epsos.eu/trc'>" +
                "<trc:PatientId>" + PATIENT_ID + "</trc:PatientId>" +
                "<trc:PurposeOfUse>" + PURPOSE_OF_USE + "</trc:PurposeOfUse>" +
                "<trc:PrescriptionId>" + PRESCRIPTION_ID + "</trc:PrescriptionId>" +
                "<trc:DispensationPinCode>" + DISPENSATION_PIN_CODE + "</trc:DispensationPinCode>" +
                "</trc:TRCParameters>"
                // @formatter:on
        );
        tokenRequirements.addCustomContent(trcParameters);

        var providerResponse = tokenProvider.createToken(providerParameters);

        Assertions.assertNotNull(providerResponse);
        Assertions.assertNotNull(providerResponse.getToken());
        Assertions.assertNotNull(providerResponse.getTokenId());

        var token = (Element) providerResponse.getToken();
        var tokenString = DOM2Writer.nodeToString(token);

        Assertions.assertTrue(tokenString.contains(providerResponse.getTokenId()));
        Assertions.assertTrue(tokenString.contains(Constants.SUBJECT_ID) && tokenString.contains(PATIENT_ID));
        Assertions.assertTrue(tokenString.contains(Constants.PURPOSE_OF_USE) && tokenString.contains(PURPOSE_OF_USE));
        Assertions.assertTrue(tokenString.contains(Constants.PRESCRIPTION_ID) && tokenString.contains(PRESCRIPTION_ID));
        Assertions.assertTrue(tokenString.contains(Constants.DISPENSATION_PIN_CODE) && tokenString.contains(DISPENSATION_PIN_CODE));
    }

    @Test
    void testTrcAssertionWithoutTrcParameters() throws Exception {
        var tokenProvider = new SAMLTokenProvider();
        tokenProvider.setAttributeStatementProviders(Collections.singletonList(new TrcAttributeStatementProvider()));

        var providerParameters = createProviderParameters();

        Assertions.assertThrows(RuntimeException.class, () -> tokenProvider.createToken(providerParameters));
    }

    @Test
    void testTrcAssertionInvalidNamespace() throws Exception {
        var tokenProvider = new SAMLTokenProvider();
        tokenProvider.setAttributeStatementProviders(Collections.singletonList(new TrcAttributeStatementProvider()));

        var providerParameters = createProviderParameters();
        var tokenRequirements = providerParameters.getTokenRequirements();

        Element trcParameters = createTrcParameters(
                // @formatter:off
                "<trc:TRCParameters xmlns:trc='http://dhp.subiger.com/trc'>" +
                        "<trc:PurposeOfUse>" + PURPOSE_OF_USE + "</trc:PurposeOfUse>" +
                        "</trc:TRCParameters>"
                // @formatter:on
        );
        tokenRequirements.addCustomContent(trcParameters);

        Assertions.assertThrows(RuntimeException.class, () -> tokenProvider.createToken(providerParameters));
    }

    @Test
    void testTrcAssertionWithoutPatientId() throws Exception {
        var tokenProvider = new SAMLTokenProvider();
        tokenProvider.setAttributeStatementProviders(Collections.singletonList(new TrcAttributeStatementProvider()));

        var providerParameters = createProviderParameters();
        var tokenRequirements = providerParameters.getTokenRequirements();

        Element trcParameters = createTrcParameters(
                // @formatter:off
                "<trc:TRCParameters xmlns:trc='http://epsos.eu/trc'>" +
                "<trc:PurposeOfUse>" + PURPOSE_OF_USE + "</trc:PurposeOfUse>" +
                "</trc:TRCParameters>"
                // @formatter:on
        );
        tokenRequirements.addCustomContent(trcParameters);

        Assertions.assertThrows(RuntimeException.class, () -> tokenProvider.createToken(providerParameters));
    }

    private TokenProviderParameters createProviderParameters() throws WSSecurityException {
        var parameters = new TokenProviderParameters();

        var tokenRequirements = new TokenRequirements();
        tokenRequirements.setTokenType(WSS4JConstants.WSS_SAML2_TOKEN_TYPE);
        parameters.setTokenRequirements(tokenRequirements);

        var keyRequirements = new KeyRequirements();
        parameters.setKeyRequirements(keyRequirements);

        parameters.setPrincipal(new CustomTokenPrincipal("Dr. John Doe"));

        var message = new MessageImpl();
        var messageContext = new WrappedMessageContext(message);
        parameters.setMessageContext(messageContext);

        StaticSTSProperties stsProperties = new StaticSTSProperties();
        Crypto crypto = CryptoFactory.getInstance(getSignatureProperties());
        stsProperties.setSignatureCrypto(crypto);
        stsProperties.setIssuer("DHP STS");
        parameters.setStsProperties(stsProperties);

        return parameters;
    }

    private Element createTrcParameters(String xml) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        var builder = factory.newDocumentBuilder();
        var source = new InputSource(new StringReader(xml));
        var document = builder.parse(source);
        return document.getDocumentElement();
    }

    private Properties getSignatureProperties() {
        var properties = new Properties();
        properties.put("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.file", "keystore.p12");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.password", "SecretPassword");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.type", "pkcs12");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.alias", "DHP STS");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.private.password", "SecretPassword");
        return properties;
    }
}
