package ascloud.cherry.auth.ctrl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

	private static final Logger LOG = LoggerFactory.getLogger(ApiController.class);

	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

	@RequestMapping("/user_info")
	public OAuth2AccessToken userInfo(OAuth2AuthenticationToken authentication) {
		LOG.info("authentication:{}", authentication);
		OAuth2AccessToken accessToken = null;
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientService
				.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(), authentication.getName());
		if (null != authorizedClient) {
			accessToken = authorizedClient.getAccessToken();
			LOG.info("accessToken:{}", accessToken.getTokenValue());
		}
		return accessToken;
	}

	@RequestMapping("/user_info/{provider}/{name}")
	public OAuth2AccessToken userInfo(@PathVariable("provider") String provider, @PathVariable("name") String name) {
		OAuth2AccessToken accessToken = null;
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient(provider, name);
		if (null != authorizedClient) {
			accessToken = authorizedClient.getAccessToken();
			LOG.info("accessToken:{}", accessToken.getTokenValue());
		}
		return accessToken;
	}

}
