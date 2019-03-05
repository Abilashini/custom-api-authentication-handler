/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.custom;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;

/**
 * Custom API authentication handler to perform authentication against a static token.
 */
public class CustomAPIAuthenticationHandler extends AbstractHandler {

    private static final Log log = LogFactory.getLog(CustomAPIAuthenticationHandler.class);

    private String customHeader;
    private String customKey;

    @Override
    public boolean handleRequest(MessageContext messageContext) {

        try {
            getAuthenticationProperties();
        } catch (CustomAPIAuthenticationHandlerException e) {
            log.error("Getting configured key details failed.", e);
            sendUnAuthorizedResponse(messageContext, HttpStatus.SC_INTERNAL_SERVER_ERROR, "Failed to read the " +
                    "configured key value.");
            return false;
        }
        Map headers = (Map) ((Axis2MessageContext) messageContext).getAxis2MessageContext().
                getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        String authHeader = (String) headers.get(customHeader);
        if (StringUtils.isEmpty(authHeader)) {
            sendUnAuthorizedResponse(messageContext, HttpStatus.SC_UNAUTHORIZED, customHeader + " is not " +
                    "found in the header");
        }

        // validates the key in the header with the configured key
        if (customKey.equalsIgnoreCase(authHeader)) {
            log.info("Custom API authentication is successful for the key: " + authHeader);
            setAuthenticationInfo(messageContext);
            return true;
        }
        log.error("Custom API authentication is failed for the key: " + authHeader);
        sendUnAuthorizedResponse(messageContext, HttpStatus.SC_UNAUTHORIZED, "Invalid token in the header.");
        return false;
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {

        return true;
    }

    /**
     * Extracts the custom header name and the key value from the configuration. This can be plugged with the custom
     * key generator/database as required
     *
     * @throws CustomAPIAuthenticationHandlerException
     */
    private void getAuthenticationProperties() throws CustomAPIAuthenticationHandlerException {

        Properties properties = new Properties();
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("custom-key.properties");
        if (inputStream != null) {
            try {
                properties.load(inputStream);
            } catch (IOException e) {
                throw new CustomAPIAuthenticationHandlerException("Error occurred when reading the configured key " +
                        "properties.", e);
            }
        }
        customHeader = properties.getProperty("Header");
        customKey = properties.getProperty("Value");
        if (StringUtils.isEmpty(customHeader) || StringUtils.isEmpty(customKey)) {
            throw new CustomAPIAuthenticationHandlerException("Missing configured custom header properties.");
        }
    }

    private void setAuthenticationInfo (MessageContext messageContext) {

        String clientIP = null;
        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Map transportHeaderMap = (Map) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        if (transportHeaderMap != null) {
            clientIP = (String) transportHeaderMap.get(APIMgtGatewayConstants.X_FORWARDED_FOR);
        }

        if (clientIP != null && !clientIP.isEmpty()) {
            if (clientIP.indexOf(",") > 0) {
                clientIP = clientIP.substring(0, clientIP.indexOf(","));
            }
        } else {
            clientIP = (String) axis2MessageContext
                    .getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        }

        AuthenticationContext authContext = new AuthenticationContext();
        authContext.setAuthenticated(true);
        authContext.setTier(APIConstants.UNAUTHENTICATED_TIER);
        authContext.setStopOnQuotaReach(true);
        authContext.setApiKey(clientIP);
        authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
        authContext.setUsername(null);
        authContext.setCallerToken(null);
        authContext.setApplicationName(null);
        authContext.setApplicationId(clientIP);
        authContext.setConsumerKey(null);
        VerbInfoDTO verbInfoDTO = new VerbInfoDTO();
        verbInfoDTO.setHttpVerb("GET");
        verbInfoDTO.setAuthType("Custom");
        verbInfoDTO.setThrottling("Unlimited");
        verbInfoDTO.setApplicableLevel("High");
        messageContext.setProperty(APIConstants.VERB_INFO_DTO, verbInfoDTO);
        APISecurityUtils.setAuthenticationContext(messageContext, authContext, null);
    }

    private void sendUnAuthorizedResponse(MessageContext messageContext, int status, String detail) {

        messageContext.setProperty(SynapseConstants.ERROR_CODE, status);
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                "API_Error_msg");
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {
            log.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        Map headers = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null) {
            axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
        }

        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {
            OMFactory fac = OMAbstractFactory.getOMFactory();
            OMNamespace ns = fac.createOMNamespace(APISecurityConstants.API_SECURITY_NS,
                    APISecurityConstants.API_SECURITY_NS_PREFIX);
            OMElement payload = fac.createOMElement("fault", ns);

            OMElement errorCode = fac.createOMElement("code", ns);
            errorCode.setText(String.valueOf(status));
            OMElement errorMessage = fac.createOMElement("message", ns);
            errorMessage.setText("Custom API authentication failed.");
            OMElement errorDetail = fac.createOMElement("description", ns);
            errorDetail.setText(detail);

            payload.addChild(errorCode);
            payload.addChild(errorMessage);
            payload.addChild(errorDetail);

            Utils.setFaultPayload(messageContext, payload);
        } else {
            Utils.setSOAPFault(messageContext, "Client", "Authentication Failure",
                    "Invalid Token");
        }
        Utils.sendFault(messageContext, status);
    }
}
