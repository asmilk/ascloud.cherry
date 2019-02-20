package ascloud.cherry.auth.model;

import java.io.Serializable;

public class User implements Serializable {
	
	private static final long serialVersionUID = -6117597470920567642L;
	
	private String username;
	
	private String password;
	
	private String rePassword;
	
	private String phone;
	
	private String redirectUrl;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getRePassword() {
		return rePassword;
	}

	public void setRePassword(String rePassword) {
		this.rePassword = rePassword;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

	@Override
	public String toString() {
		return "User [username=" + username + ", password=" + password + ", rePassword=" + rePassword + ", phone="
				+ phone + ", redirectUrl=" + redirectUrl + "]";
	}

}
