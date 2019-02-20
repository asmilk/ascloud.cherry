package ascloud.cherry.auth.security;

import java.io.IOException;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

@Component
public class MyOAuth2LogoutHandler implements LogoutHandler {

	private static final Logger LOG = LoggerFactory.getLogger(MyOAuth2LogoutHandler.class);

	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

		LOG.info("authentication:{}", authentication);
		if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oauthAuth = (OAuth2AuthenticationToken) authentication;

			OAuth2AuthorizedClient authorizedClient = this.authorizedClientService
					.loadAuthorizedClient(oauthAuth.getAuthorizedClientRegistrationId(), oauthAuth.getName());
			if (null != authorizedClient) {
				OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
				LOG.info("accessToken:{}", accessToken.getTokenValue());
				
				try {
					URL url = new URL("http", "oauth2.server", 8822, "/uaa/revoke_token");
					LOG.info("url:{}", url);
					HTTPRequest req = new HTTPRequest(HTTPRequest.Method.GET, url);
					req.setHeader("Authorization", "Bearer " + accessToken.getTokenValue());
					HTTPResponse res = req.send();
					String content = res.getContent();
					LOG.info("content:{}", content);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

}
