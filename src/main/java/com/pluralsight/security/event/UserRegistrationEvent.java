package com.pluralsight.security.event;

import com.pluralsight.security.entity.CryptoUser;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class UserRegistrationEvent extends ApplicationEvent {
    private final CryptoUser user;

    public UserRegistrationEvent(CryptoUser user){
        super(user);
        this.user = user;
    }

}
