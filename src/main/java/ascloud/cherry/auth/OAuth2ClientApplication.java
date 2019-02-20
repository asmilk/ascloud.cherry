package ascloud.cherry.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.extras.springsecurity5.dialect.SpringSecurityDialect;
import org.thymeleaf.spring5.SpringTemplateEngine;

import ascloud.cherry.auth.security.MyAuthenticationSuccessHandler;
import ascloud.cherry.auth.security.MyAuthorizationCodeTokenResponseClient;
import ascloud.cherry.auth.security.MyOAuth2AuthorizationRequestRedirectFilter;
import ascloud.cherry.auth.security.MyOAuth2LoginAuthenticationFilter;
import ascloud.cherry.auth.security.MyOAuth2LogoutHandler;
import ascloud.cherry.auth.security.MyOAuth2UserService;

@SpringBootApplication
public class OAuth2ClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuth2ClientApplication.class, args);
	}

	@Bean
	public TemplateEngine templateEngine() {
		SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();
		springTemplateEngine.addDialect(new SpringSecurityDialect());
		return springTemplateEngine;
	}

	@Configuration
	@EnableWebMvc
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final Logger LOG = LoggerFactory.getLogger(WebSecurityConfig.class);

		@Autowired
		private ClientRegistrationRepository clientRegistrationRepository;
		@Autowired
		private OAuth2AuthorizedClientService authorizedClientService;
		@Autowired
		private MyOAuth2LogoutHandler logoutHandler;

		@Value("${ascloud.security.oauth2.client.provider.uaa.logout-uri}")
		private String authServerLogoutUrl;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			LOG.info("====WebSecurityConfig.configure(HttpSecurity)====");
			LOG.info("clientRegistrationRepository:{}", clientRegistrationRepository);
			LOG.info("authorizedClientService:{}", authorizedClientService);

			MyOAuth2LoginAuthenticationFilter myOAuth2LoginAuthenticationFilter = new MyOAuth2LoginAuthenticationFilter(
					this.clientRegistrationRepository, this.authorizedClientService);
			myOAuth2LoginAuthenticationFilter.setAuthenticationManager(super.authenticationManagerBean());
			myOAuth2LoginAuthenticationFilter
					.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/index"));
			myOAuth2LoginAuthenticationFilter.setAuthenticationSuccessHandler(
					new MyAuthenticationSuccessHandler("http://oauth2.com/oauth/account"));

			MyOAuth2AuthorizationRequestRedirectFilter myOAuth2AuthorizationRequestRedirectFilter = new MyOAuth2AuthorizationRequestRedirectFilter(
					this.clientRegistrationRepository);

			http//
					.authorizeRequests().antMatchers("/api/**", "/index", "/login/**").permitAll().anyRequest()
					.authenticated().and()//
					.csrf().disable()//
					.addFilterAt(myOAuth2LoginAuthenticationFilter, OAuth2LoginAuthenticationFilter.class)//
					.addFilterAt(myOAuth2AuthorizationRequestRedirectFilter,
							OAuth2AuthorizationRequestRedirectFilter.class)
					.logout().addLogoutHandler(logoutHandler).logoutSuccessUrl(this.authServerLogoutUrl).and()//
					.oauth2Login().loginPage("/index")//
					.tokenEndpoint().accessTokenResponseClient(new MyAuthorizationCodeTokenResponseClient()).and()//
					.userInfoEndpoint().userService(new MyOAuth2UserService());
		}

		@Override
		public void configure(WebSecurity web) throws Exception {
			web.ignoring().antMatchers("/favicon.ico");
		}

	}

}
