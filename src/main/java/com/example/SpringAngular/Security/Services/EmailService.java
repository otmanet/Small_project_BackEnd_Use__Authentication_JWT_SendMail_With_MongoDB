package com.example.SpringAngular.Security.Services;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
@Service
public class EmailService {
    @Autowired
    private JavaMailSender javaMailSender;

    public EmailService(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    public ResponseEntity<?> sendMail(String emailUSer,String UrlToken){
        String from =  "CRM_School";
        SimpleMailMessage message =  new SimpleMailMessage();
        String urlSend = "http://localhost:3000/api/auth/password-reset?token="+UrlToken;
        message.setFrom(from);
        message.setTo(emailUSer);
        message.setSubject("Reset password for  CRM School");
        message.setText("<html>" +
                "<body>" +
                "<p>Click the following link:</p>" +
                "<a href='" + urlSend + "'>" + urlSend + "</a>" +
                "</body>" +
                "</html>");
        javaMailSender.send(message);
        return ResponseEntity.ok("mail send success");
    }

}
