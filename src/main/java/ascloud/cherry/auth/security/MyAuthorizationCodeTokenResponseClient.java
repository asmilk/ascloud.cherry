package ascloud.cherry.auth.security;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.CollectionUtils;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;

import net.minidev.json.JSONObject;

public class MyAuthorizationCodeTokenResponseClient extends NimbusAuthorizationCodeTokenResponseClient {

	private static final Logger LOG = LoggerFactory.getLogger(MyAuthorizationCodeTokenResponseClient.class);

	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest)
			throws OAuth2AuthenticationException {

		ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();

		// Build the authorization code grant request for the token endpoint
		AuthorizationCode authorizationCode = new AuthorizationCode(
				authorizationGrantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode());
		URI redirectUri = toURI(
				authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getRedirectUri());
		AuthorizationGrant authorizationCodeGrant = new AuthorizationCodeGrant(authorizationCode, redirectUri);
		URI tokenUri = toURI(clientRegistration.getProviderDetails().getTokenUri());

		// Set the credentials to authenticate the client at the token endpoint
		ClientID clientId = new ClientID(clientRegistration.getClientId());
		Secret clientSecret = new Secret(clientRegistration.getClientSecret());
		ClientAuthentication clientAuthentication;
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			clientAuthentication = new ClientSecretPost(clientId, clientSecret);
		} else {
			clientAuthentication = new ClientSecretBasic(clientId, clientSecret);
		}

		String registrationId = clientRegistration.getRegistrationId();
		com.nimbusds.oauth2.sdk.TokenResponse tokenResponse;
		try {
			Map<String, String> customParams = new HashMap<>();
			if ("qq".equalsIgnoreCase(registrationId)) {
				customParams.put("client_id", clientId.getValue());
				customParams.put("client_secret", clientSecret.getValue());
			} else if ("weixin".equalsIgnoreCase(registrationId)) {
				customParams.put("appid", clientId.getValue());
				customParams.put("secret", clientSecret.getValue());
			}
			// Send the Access Token request
			TokenRequest tokenRequest = new TokenRequest(tokenUri, clientAuthentication, authorizationCodeGrant, null,
					customParams);
			HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
			httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
			httpRequest.setConnectTimeout(30000);
			httpRequest.setReadTimeout(30000);

			HTTPResponse httpResponse = httpRequest.send();
			JSONObject jsonObject = new JSONObject();
			if ("qq".equalsIgnoreCase(registrationId)) {
				String content = httpResponse.getContent();
				Pattern pattern = Pattern.compile("(?<key>\\w+)=(?<value>\\w+)");
				Matcher matcher = pattern.matcher(content);
				while (matcher.find()) {
					String key = matcher.group("key");
					String value = matcher.group("value");
					LOG.info("{}:{}", key, value);
					jsonObject.put(key, value);
				}
			} else {
				httpResponse.setHeader("Content-Type", "application/json; charset=UTF-8");
				jsonObject = httpResponse.getContentAsJSONObject();
			}
			jsonObject.putIfAbsent("token_type", "bearer");
			tokenResponse = com.nimbusds.oauth2.sdk.TokenResponse.parse(jsonObject);
		} catch (ParseException pe) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
					"An error occurred parsing the Access Token response: " + pe.getMessage(), null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), pe);
		} catch (IOException ioe) {
			throw new AuthenticationServiceException(
					"An error occurred while sending the Access Token Request: " + ioe.getMessage(), ioe);
		}

		if (!tokenResponse.indicatesSuccess()) {
			TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
			ErrorObject errorObject = tokenErrorResponse.getErrorObject();
			OAuth2Error oauth2Error = new OAuth2Error(errorObject.getCode(), errorObject.getDescription(),
					(errorObject.getURI() != null ? errorObject.getURI().toString() : null));
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

		String accessToken = accessTokenResponse.getTokens().getAccessToken().getValue();
		OAuth2AccessToken.TokenType accessTokenType = null;
		if (OAuth2AccessToken.TokenType.BEARER.getValue()
				.equalsIgnoreCase(accessTokenResponse.getTokens().getAccessToken().getType().getValue())) {
			accessTokenType = OAuth2AccessToken.TokenType.BEARER;
		}
		long expiresIn = accessTokenResponse.getTokens().getAccessToken().getLifetime();

		// As per spec, in section 5.1 Successful Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-5.1
		// If AccessTokenResponse.scope is empty, then default to the scope
		// originally requested by the client in the Authorization Request
		Set<String> scopes;
		if (CollectionUtils.isEmpty(accessTokenResponse.getTokens().getAccessToken().getScope())) {
			scopes = new LinkedHashSet<>(
					authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getScopes());
		} else {
			scopes = new LinkedHashSet<>(accessTokenResponse.getTokens().getAccessToken().getScope().toStringList());
		}

		Map<String, Object> additionalParameters = new LinkedHashMap<>(accessTokenResponse.getCustomParameters());

		OAuth2AccessTokenResponse oAuth2AccessTokenResponse = OAuth2AccessTokenResponse.withToken(accessToken)
				.tokenType(accessTokenType).expiresIn(expiresIn).scopes(scopes)
				.additionalParameters(additionalParameters).build();
		
		OAuth2AccessToken oAuth2AccessToken = oAuth2AccessTokenResponse.getAccessToken();
		MyOAuth2AccessToken myOAuth2AccessToken = new MyOAuth2AccessToken(oAuth2AccessToken.getTokenType(),
				oAuth2AccessToken.getTokenValue(), oAuth2AccessToken.getIssuedAt(),
				oAuth2AccessToken.getExpiresAt(), oAuth2AccessToken.getScopes());
		
			try {
				Field field = OAuth2AccessTokenResponse.class.getDeclaredField("accessToken");
				field.setAccessible(true);
				if ("weixin".equalsIgnoreCase(registrationId)) {
					myOAuth2AccessToken.setOpenid(additionalParameters.get("openid").toString());
				} else if ("weibo".equalsIgnoreCase(registrationId)) {
					myOAuth2AccessToken.setUid(additionalParameters.get("uid").toString());
				}
				field.set(oAuth2AccessTokenResponse, myOAuth2AccessToken);
			} catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		
		return oAuth2AccessTokenResponse;
	}

	private static URI toURI(String uriStr) {
		try {
			return new URI(uriStr);
		} catch (Exception ex) {
			throw new IllegalArgumentException("An error occurred parsing URI: " + uriStr, ex);
		}
	}

}
