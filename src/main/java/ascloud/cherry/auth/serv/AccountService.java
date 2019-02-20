package ascloud.cherry.auth.serv;

import java.util.Optional;

import javax.transaction.Transactional;

import ascloud.cherry.auth.enty.AccountEntity;

@Transactional
public interface AccountService {
	
	Optional<AccountEntity> findByProviderAndUsername(String provider, String username);
	
	Optional<AccountEntity> findByProviderAndPhone(String provider, String phone);
	
	Optional<AccountEntity> findByOtherProvider(String provider, String username, String otherProvider);
	
	AccountEntity save(AccountEntity entity);

}
