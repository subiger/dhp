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
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.opensaml.saml.saml2.core.Attribute;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * @author Renaud Subiger
 * @since 1.0.0
 */
public class TrcAttributeStatementProvider implements AttributeStatementProvider {

    @Override
    public AttributeStatementBean getStatement(TokenProviderParameters providerParameters) {
        var tokenRequirements = providerParameters.getTokenRequirements();
        var trcParameters = getTrcParameters(tokenRequirements.getCustomContent());

        var attributeStatement = new AttributeStatementBean();

        createAttribute(attributeStatement, "XSPA Subject", Constants.SUBJECT_ID, getPatientId(trcParameters));

        getParameter(trcParameters, "PurposeOfUse")
                .ifPresent(value -> createAttribute(attributeStatement, "XSPA Purpose Of Use", Constants.PURPOSE_OF_USE, value));
        getParameter(trcParameters, "PrescriptionId")
                .ifPresent(value -> createAttribute(attributeStatement, "Prescription ID", Constants.PRESCRIPTION_ID, value));
        getParameter(trcParameters, "DispensationPinCode")
                .ifPresent(value -> createAttribute(attributeStatement, "Dispensation Pin Code", Constants.DISPENSATION_PIN_CODE, value));

        return attributeStatement;
    }

    private Element getTrcParameters(List<Object> customContent) {
        return customContent.stream()
                .filter(Element.class::isInstance)
                .map(Element.class::cast)
                .filter(element -> Objects.equals(element.getNamespaceURI(), Constants.TRC_NS_URI) &&
                        Objects.equals(element.getLocalName(), "TRCParameters"))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Element 'TRCParameters' is missing"));
    }

    private String getPatientId(Element trcParameters) {
        return getParameter(trcParameters, "PatientId")
                .orElseThrow(() -> new RuntimeException("PatientId is required"));
    }

    private Optional<String> getParameter(Element trcParameters, String localName) {
        NodeList nodes = trcParameters.getElementsByTagNameNS(Constants.TRC_NS_URI, localName);
        if (nodes.getLength() == 0) {
            return Optional.empty();
        }
        return Optional.of(nodes.item(0).getTextContent());
    }

    private void createAttribute(AttributeStatementBean attributeStatement, String simpleName, String qualifiedName, Object value) {
        var attribute = new AttributeBean();
        attribute.setSimpleName(simpleName);
        attribute.setQualifiedName(qualifiedName);
        attribute.setNameFormat(Attribute.URI_REFERENCE);
        attribute.addAttributeValue(value);
        attributeStatement.getSamlAttributes().add(attribute);
    }
}
