package ascloud.cherry.auth.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

public class MyAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private static final Logger LOG = LoggerFactory.getLogger(MyAuthenticationSuccessHandler.class);

	public MyAuthenticationSuccessHandler(String defaultTargetUrl) {
		super(defaultTargetUrl);
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		LOG.info("authentication:{}", authentication);

		LOG.info("====request.parameters====");
		Map<String, String[]> parameterMap = request.getParameterMap();
		for (Entry<String, String[]> entry : parameterMap.entrySet()) {
			LOG.info("{}:{}", entry.getKey(), Arrays.toString(entry.getValue()));
		}

		LOG.info("====request.headers====");
		Enumeration<String> headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String name = headerNames.nextElement();
			Enumeration<String> headers = request.getHeaders(name);
			while (headers.hasMoreElements()) {
				LOG.info("{}:{}", name, headers.nextElement());
			}

		}

		if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
			LOG.info("authentication:{}", oAuth2AuthenticationToken.getDetails());
			String authorizedClientRegistrationId = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();
			String name = oAuth2AuthenticationToken.getName();
			LOG.info("authorizedClientRegistrationId:{}", authorizedClientRegistrationId);
			LOG.info("name:{}", name);

			this.clearAuthenticationAttributes(request);
			this.getRedirectStrategy().sendRedirect(request, response,
					this.getDefaultTargetUrl()/* + "/" + authorizedClientRegistrationId + "/" + name*/);
		}
	}
}
