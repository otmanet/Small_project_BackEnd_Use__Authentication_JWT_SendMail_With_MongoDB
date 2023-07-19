package com.example.SpringAngular.payload.request;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class ResetPassword {

    private String emailSend;

    @NotBlank
    @Size(max =120)
    private String password;
    
    public String getEmailSend() {
        return emailSend;
    }

    
    public String getPassword() {
		return password;
	}


	public void setPassword(String password) {
		this.password = password;
	}


	public void setEmailSend(String emailSend) {
        this.emailSend = emailSend;
    }
}
