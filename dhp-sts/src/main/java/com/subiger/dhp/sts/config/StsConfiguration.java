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

package com.subiger.dhp.sts.config;

import com.subiger.dhp.sts.Constants;
import com.subiger.dhp.sts.token.TrcAttributeStatementProvider;
import org.apache.cxf.Bus;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.rt.security.SecurityConstants;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;
import org.apache.cxf.ws.security.sts.provider.operation.IssueOperation;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import java.util.Collections;
import java.util.Properties;

/**
 * @author Renaud Subiger
 * @since 1.0.0
 */
@Configuration
@EnableConfigurationProperties(StsProperties.class)
public class StsConfiguration {

    @Bean
    public Endpoint endpoint(Bus bus, SecurityTokenServiceProvider provider, Properties signatureCryptoProperties) {
        var endpoint = new EndpointImpl(bus, provider);
        endpoint.setWsdlLocation("classpath:/wsdl/trc-sts.wsdl");
        endpoint.setServiceName(new QName(Constants.WS_TRUST_SERVICE_NS_URI, "SecurityTokenService"));
        endpoint.setEndpointName(new QName(Constants.WS_TRUST_SERVICE_NS_URI, "SecurityTokenServicePort"));
        endpoint.publish("/trc-sts");
        endpoint.getProperties().put(SecurityConstants.SIGNATURE_PROPERTIES, signatureCryptoProperties);
        return endpoint;
    }

    @Bean
    public SecurityTokenServiceProvider provider(IssueOperation issueOperation) {
        try {
            var provider = new SecurityTokenServiceProvider();
            provider.setIssueOperation(issueOperation);
            return provider;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Bean
    public IssueOperation issueOperation(StaticSTSProperties stsProperties, SAMLTokenProvider tokenProvider) {
        var issueOperation = new TokenIssueOperation();
        issueOperation.setTokenProviders(Collections.singletonList(tokenProvider));
        issueOperation.setStsProperties(stsProperties);
        issueOperation.setAllowCustomContent(true);
        return issueOperation;
    }

    @Bean
    public StaticSTSProperties stsProperties(StsProperties properties, Properties signatureCryptoProperties) {
        var stsProperties = new StaticSTSProperties();
        stsProperties.setIssuer(properties.getIssuer());
        stsProperties.setSignatureCryptoProperties(signatureCryptoProperties);
        return stsProperties;
    }

    @Bean
    public SAMLTokenProvider tokenProvider() {
        var tokenProvider = new SAMLTokenProvider();
        tokenProvider.setAttributeStatementProviders(Collections.singletonList(new TrcAttributeStatementProvider()));
        return tokenProvider;
    }

    @Bean
    public Properties signatureCryptoProperties(StsProperties properties) {
        var signatureCryptoProperties = new Properties();
        signatureCryptoProperties.putAll(properties.getProperties());
        return signatureCryptoProperties;
    }
}
