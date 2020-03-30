package com.pluralsight.security.event;

import com.pluralsight.security.service.VerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationListener;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailVerificationListener implements ApplicationListener<UserRegistrationEvent> {

    private final JavaMailSender mailSender;
    private final VerificationService verificationService;

    @Override
    public void onApplicationEvent(UserRegistrationEvent event) {
        String username = event.getUser().getUsername();
        String verificationId = verificationService.createVerification(username);
        String email = event.getUser().getEmail();
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject("Crypto Profile Account Verification");
        message.setText("Account activation link: https://localhost:8443/verify/email?id="+verificationId);
        message.setTo(email);
        mailSender.send(message);
    }
}
