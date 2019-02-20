package ascloud.cherry.auth.ctrl;

import java.io.IOException;
import java.net.URL;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import ascloud.cherry.auth.enty.AccountEntity;
import ascloud.cherry.auth.model.User;
import ascloud.cherry.auth.serv.AccountService;

@Controller
@RequestMapping("/oauth")
public class OAuth2Controller {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2Controller.class);

	@Autowired
	private AccountService accountService;

	@RequestMapping("/account")
	public String account(OAuth2AuthenticationToken authentication, @ModelAttribute("user") User user)
			throws IOException {
		LOG.info("authentication:{}", authentication);
		String provider = authentication.getAuthorizedClientRegistrationId();
		String name = authentication.getName();
		LOG.info("provider:{}", provider);
		LOG.info("name:{}", name);

		if (null != provider && !"uaa".equals(provider)) {
			Optional<AccountEntity> optional = this.accountService.findByOtherProvider(provider, name, "uaa");
			if (optional.isPresent()) {
				AccountEntity accountEntity = optional.get();
				LOG.info("accountEntity:{}", accountEntity);

				URL url = new URL("http", "oauth2.server", 8822, "/user/" + accountEntity.getUsername());
				LOG.info("url:{}", url);
				HTTPRequest req = new HTTPRequest(HTTPRequest.Method.GET, url);
				HTTPResponse res = req.send();
				String content = res.getContent();
				LOG.info("content:{}", content);
				user.setUsername(accountEntity.getUsername());
				user.setPassword("123456");
				user.setRedirectUrl(
						"http://oauth2.server:8822/oauth/authorize?response_type=code&client_id=uaa&scope=all&state=autoLogin&redirect_uri=http://oauth2.com/login/oauth2/code/uaa");
				return "login";
			} else {
				return "account";
			}
		}
		return "index";
	}

	@PostMapping("/register")
	public String register(OAuth2AuthenticationToken authentication, @ModelAttribute("user") User user)
			throws IOException {
		LOG.info("====OAuth2Controller.register====");

		String provider = authentication.getAuthorizedClientRegistrationId();
		String name = authentication.getName();
		LOG.info("provider:{}", provider);
		LOG.info("name:{}", name);

		AccountEntity entity = new AccountEntity();
		entity.setUsername(name);
		entity.setProvider(provider);
		entity.setPhone(user.getPhone());
		entity = this.accountService.save(entity);
		LOG.info("entity:{}", entity);

		Optional<AccountEntity> optional = this.accountService.findByProviderAndPhone("uaa", user.getPhone());
		if (optional.isPresent()) {
			AccountEntity accountEntity = optional.get();
			LOG.info("accountEntity:{}", accountEntity);
			
			URL url = new URL("http", "oauth2.server", 8822, "/user/" + accountEntity.getUsername());
			LOG.info("url:{}", url);
			HTTPRequest req = new HTTPRequest(HTTPRequest.Method.GET, url);
			HTTPResponse res = req.send();
			String content = res.getContent();
			LOG.info("content:{}", content);
			
			user.setUsername(accountEntity.getUsername());
			user.setPassword("123456");			
		} else {
			URL url = new URL("http", "oauth2.server", 8822, "/user/register");
			LOG.info("url:{}", url);
			HTTPRequest req = new HTTPRequest(HTTPRequest.Method.POST, url);
			req.setQuery("username=" + user.getUsername() + "&password=" + user.getPassword());
			HTTPResponse res = req.send();
			String content = res.getContent();
			LOG.info("content:{}", content);

			AccountEntity entityUaa = new AccountEntity();
			entityUaa.setUsername(user.getUsername());
			entityUaa.setProvider("uaa");
			entityUaa.setPhone(user.getPhone());
			entityUaa = this.accountService.save(entityUaa);
			LOG.info("entityUaa:{}", entityUaa);
		}

		user.setRedirectUrl(
				"http://oauth2.server:8822/oauth/authorize?response_type=code&client_id=uaa&scope=all&state=autoLogin&redirect_uri=http://oauth2.com/login/oauth2/code/uaa");
		LOG.info("user:{}", user);

		return "login";
	}

}
