package com.pluralsight.security.service;

import com.pluralsight.security.model.ListTransactionsDto;
import com.pluralsight.security.model.PortfolioPositionsDto;

import java.util.List;

public interface PortfolioQueryService {

	PortfolioPositionsDto getPortfolioPositions();
	PortfolioPositionsDto getPortfolioPositions(String id);
	ListTransactionsDto getPortfolioTransactions();
    PortfolioPositionsDto getPortfolioPositionsForUser(String username);
	List<String> getPortfolioIds();

}
