package com.pluralsight.security.service;

import java.math.BigDecimal;
import java.util.ArrayList;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import com.pluralsight.security.entity.CryptoCurrency;
import com.pluralsight.security.entity.Portfolio;
import com.pluralsight.security.entity.Transaction;
import com.pluralsight.security.entity.Type;
import com.pluralsight.security.model.AddTransactionToPortfolioDto;
import com.pluralsight.security.repository.CryptoCurrencyRepository;
import com.pluralsight.security.repository.PortfolioRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class PortfolioCommandServiceNoSql implements PortfolioCommandService {

	private final PortfolioRepository portfolioRepositiory;
	private final CryptoCurrencyRepository currencyRepository;
	
	@Override
	//The filter object will validate each user from request transaction dto if not found
	//it will remove the user
	@PreAuthorize("hasRole('ADMIN') or filterObject.username == authentication.username")
	public void addTransactionToPortfolio(AddTransactionToPortfolioDto request) {
		Portfolio portfolio = portfolioRepositiory.findByUsername(getUsername());
		Transaction transaction = createTransactionEntity(request);
		portfolio.addTransaction(transaction);
		portfolioRepositiory.save(portfolio);
	}
	
	@Override
	public void removeTransactionFromPortfolio(String transactionId) {
		Portfolio portfolio = portfolioRepositiory.findByUsername(getUsername());
		Transaction transacion = portfolio.getTransactionById(transactionId);
		portfolio.deleteTransaction(transacion);
		portfolioRepositiory.save(portfolio);
	}

	@Override
	public boolean userHasAportfolio(String username) {
		return portfolioRepositiory.existsByUsername(username);
	}

	@Override
	public void createNewPortfolio(String username) {
		portfolioRepositiory.save(new Portfolio(username, new ArrayList<>()));
	}

	private String getUsername() {
		Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		return ((User)principle).getUsername();
	}
	
	private Transaction createTransactionEntity(AddTransactionToPortfolioDto request) {
		CryptoCurrency crpytoCurrency = currencyRepository.findBySymbol(request.getCryptoSymbol());
		Type type = Type.valueOf(request.getType());
		BigDecimal quantity = new BigDecimal(request.getQuantity());
		BigDecimal price = new BigDecimal(request.getPrice());
		Transaction transaction = new Transaction(crpytoCurrency, type, quantity, price,System.currentTimeMillis());
		return transaction;
	}

}
