# custom-api-authentication-handler

### Instructions:
1. Add the custom header name and the key value to the custom-key.properties file located at src/main/resources
    eg:
    ```
        Header=X-custom-key
        Value=ABCD1234
    ```
2. Build the project using maven `mvn clean install`
3. Locate the handler target/custom-api-authentication-handler-1.0-SNAPSHOT.jar to 
<APIM_HOME>/repository/components/dropins
4. Configure the following template to the velocity_template.xml located at <APIM_HOME>/repository/resources/api_templates
    * To apply the custom handler for all the APIs
    ```
        <handlers xmlns="http://ws.apache.org/ns/synapse">
               #foreach($handler in $handlers)
                  #if(!($handler.className == "org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler"))
                   <handler xmlns="http://ws.apache.org/ns/synapse" class="$handler.className">
                    #if($handler.hasProperties())
                        #set ($map = $handler.getProperties() )
                        #foreach($property in $map.entrySet())
                            <property name="$!property.key" value="$!property.value"/>
                        #end
                    #end
                   </handler>
        	  #else
        		<handler class="org.wso2.custom.CustomAPIAuthenticationHandler" />
        	  #end
                #end
        </handlers>
    ```
    * To apply the custom handler only for specific APIs
    Add the API names to the 'customAuthAPIList'
    ```
        <handlers xmlns="http://ws.apache.org/ns/synapse">
        #set ($customAuthAPIList = ["api_name_1","api_name_2"])
        #foreach($handler in $handlers)
            #if(!$customAuthAPIList.contains($apiName) || !($handler.className == "org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler"))
                <handler xmlns="http://ws.apache.org/ns/synapse" class="$handler.className">
                    #if($handler.hasProperties())
                        #set ($map = $handler.getProperties() )
                        #foreach($property in $map.entrySet())
                            <property name="$!property.key" value="$!property.value"/>
                        #end
                    #end
                </handler>
              #else
                <handler class="org.wso2.custom.CustomAPIAuthenticationHandler" />
            #end
        #end
        </handlers>
    ```
The above ways of handler configuration will apply the custom handler to the newly created APIs and re-published 
APIs. If required to change the authentication handler of the existing APIs, then replace the default API 
authentication handler, 
```      
<handler class="org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler">
     <property name="RemoveOAuthHeadersFromOutMessage" value="true"/>
     <property name="APILevelPolicy" value=""/>
     <property name="APISecurity" value="oauth2"/>
</handler>
``` 
with the custom API authentication handler, 
```
<handler class="org.wso2.custom.CustomAPIAuthenticationHandler"/>
``` 
in the synapse Configuration file of the API 
located at <APIM_HOME>/repository/deployment/server/synapse-configs/default/api
    
