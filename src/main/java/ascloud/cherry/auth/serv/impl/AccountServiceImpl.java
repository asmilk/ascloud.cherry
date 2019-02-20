package ascloud.cherry.auth.serv.impl;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import ascloud.cherry.auth.enty.AccountEntity;
import ascloud.cherry.auth.repo.AccountRepository;
import ascloud.cherry.auth.serv.AccountService;

@Service
public class AccountServiceImpl implements AccountService {
	
	@Autowired
	private AccountRepository accountRepository;

	@Override
	public Optional<AccountEntity> findByProviderAndUsername(String provider, String username) {
		return this.accountRepository.findByProviderAndUsername(provider, username);
	}

	@Override
	public Optional<AccountEntity> findByProviderAndPhone(String provider, String phone) {
		return this.accountRepository.findByProviderAndPhone(provider, phone);
	}

	@Override
	public Optional<AccountEntity> findByOtherProvider(String provider, String username, String otherProvider) {
		return this.accountRepository.findByOtherProvider(provider, username, otherProvider);
	}

	@Override
	public AccountEntity save(AccountEntity entity) {
		return this.accountRepository.save(entity);
	}

}
