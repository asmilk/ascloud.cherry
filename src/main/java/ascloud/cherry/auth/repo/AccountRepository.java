package ascloud.cherry.auth.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import ascloud.cherry.auth.enty.AccountEntity;

@Repository
public interface AccountRepository extends JpaRepository<AccountEntity, Long> {
	
	Optional<AccountEntity> findByProviderAndUsername(String provider, String username);
	
	Optional<AccountEntity> findByProviderAndPhone(String provider, String phone);
	
	@Query("select a from #{#entityName} a where exists (select 1 from #{#entityName} b where b.phone = a.phone and b.provider = ?1 and b.username = ?2 and a.provider = ?3)")
	Optional<AccountEntity> findByOtherProvider(String provider, String username, String otherProvider);

}
