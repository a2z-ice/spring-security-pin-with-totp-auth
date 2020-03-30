package com.pluralsight.security.userdetails;

import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class AdditionalAuthenticationDetails extends WebAuthenticationDetails {

    @Getter
    private String securityPin;

    public AdditionalAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.securityPin = request.getParameter("securityPin");
    }
}
