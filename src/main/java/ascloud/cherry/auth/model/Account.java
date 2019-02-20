package ascloud.cherry.auth.model;

import java.io.Serializable;
import java.time.Instant;
import java.time.LocalDateTime;

public class Account implements Serializable {

	private static final long serialVersionUID = 4006931968508541262L;

	private Long id;

	private String name;

	private LocalDateTime createdDate;

	private Instant updatedDate;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public LocalDateTime getCreatedDate() {
		return createdDate;
	}

	public void setCreatedDate(LocalDateTime createdDate) {
		this.createdDate = createdDate;
	}

	public Instant getUpdatedDate() {
		return updatedDate;
	}

	public void setUpdatedDate(Instant updatedDate) {
		this.updatedDate = updatedDate;
	}

	@Override
	public String toString() {
		return "Account [id=" + id + ", name=" + name + ", createdDate=" + createdDate + ", updatedDate=" + updatedDate
				+ "]";
	}

}
