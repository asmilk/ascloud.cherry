package ascloud.cherry.auth.enty;

import static javax.persistence.GenerationType.IDENTITY;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity(name = "ACCOUNT")
public class AccountEntity implements Serializable {

	private static final long serialVersionUID = 3744559691165435014L;

	@Id
	@GeneratedValue(strategy = IDENTITY)
	private Long id;
	
	private String provider;
	
	private String username;
	
	private String phone;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	@Override
	public String toString() {
		return "AccountEntity [id=" + id + ", provider=" + provider + ", username=" + username + ", phone=" + phone
				+ "]";
	}

}
