package ascloud.cherry.auth.ctrl;

import java.time.Instant;
import java.time.LocalDateTime;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import ascloud.cherry.auth.model.Account;
import ascloud.cherry.auth.model.User;

@Controller
public class IndexController {

	private static final Logger LOG = LoggerFactory.getLogger(IndexController.class);

	@RequestMapping({ "/", "/index" })
	public String index(@ModelAttribute("user") User user, HttpServletRequest request) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof AnonymousAuthenticationToken) {
			return "redirect:/oauth2/authorization/uaa";
		} else if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
			String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
			LOG.info("clientRegistrationId:{}", clientRegistrationId);
		}
		return "index";
	}

	@RequestMapping("/account")
	@ResponseBody
	public Account account() {
		Account account = new Account();
		account.setId(123L);
		account.setName("asmilk");
		account.setCreatedDate(LocalDateTime.now());
		account.setUpdatedDate(Instant.now());
		return account;
	}

}
