package ascloud.cherry.auth.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;

public class MyOAuth2LoginAuthenticationFilter extends OAuth2LoginAuthenticationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(MyOAuth2LoginAuthenticationFilter.class);

	public MyOAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService) {
		super(clientRegistrationRepository, authorizedClientService);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		Authentication preAuthentication = SecurityContextHolder.getContext().getAuthentication();
		LOG.info("preAuthentication:{}", preAuthentication);
		if (preAuthentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) preAuthentication;
			LOG.info("clientRegistrationId:{}", oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());
			LOG.info("principalName:{}", oAuth2AuthenticationToken.getName());
		}
		return super.attemptAuthentication(request, response);
	}

}
