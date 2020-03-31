package com.pluralsight.security.service;

import com.pluralsight.security.model.AddTransactionToPortfolioDto;

public interface PortfolioCommandService {

	void addTransactionToPortfolio(AddTransactionToPortfolioDto request);
	void removeTransactionFromPortfolio(String transactionId);
    boolean userHasAportfolio(String username);
	void createNewPortfolio(String username);
}
