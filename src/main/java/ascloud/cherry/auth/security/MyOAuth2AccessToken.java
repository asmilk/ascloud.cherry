package ascloud.cherry.auth.security;

import java.time.Instant;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

public class MyOAuth2AccessToken extends OAuth2AccessToken {

	private static final long serialVersionUID = 2215922263814217542L;
	
	private String openid;
	
	private String uid;
	
	public MyOAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt,
			Set<String> scopes) {
		super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
	}

	public MyOAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt) {
		super(tokenType, tokenValue, issuedAt, expiresAt);
	}

	public String getOpenid() {
		return openid;
	}

	public void setOpenid(String openid) {
		this.openid = openid;
	}

	public String getUid() {
		return uid;
	}

	public void setUid(String uid) {
		this.uid = uid;
	}

}
