package ascloud.cherry.auth.security;

import java.net.URI;
import java.util.Set;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class MyOAuth2AuthorizationRequestUriBuilder {

	public URI build(OAuth2AuthorizationRequest authorizationRequest) {
		Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
		Set<String> scopes = authorizationRequest.getScopes();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(authorizationRequest.getAuthorizationUri())
				.queryParam(OAuth2ParameterNames.RESPONSE_TYPE, authorizationRequest.getResponseType().getValue())
				.queryParam(OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getClientId())
				.queryParam(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(scopes, " "))
				.queryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		if (authorizationRequest.getRedirectUri() != null) {
			uriBuilder.queryParam(OAuth2ParameterNames.REDIRECT_URI, authorizationRequest.getRedirectUri());
		}

		return uriBuilder.build().encode().toUri();
	}

}
