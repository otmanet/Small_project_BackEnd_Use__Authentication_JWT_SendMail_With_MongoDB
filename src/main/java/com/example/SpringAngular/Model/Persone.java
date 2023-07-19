package com.example.SpringAngular.Model;

import org.hibernate.annotations.GeneratorType;

import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.Date;

public class Persone {

    private Long id;
    private  String firstname;
    private String lastname;
    private String  birthday;
    private String city;

    public Persone() {
        super();
    }

    public Persone(Long id, String firstname, String lastname, String birthday, String city) {
        this.id = id;
        this.firstname = firstname;
        this.lastname = lastname;
        this.birthday = birthday;
        this.city = city;
    }

    public Persone(String firstname, String lastname, String birthday, String city) {
        this.firstname = firstname;
        this.lastname = lastname;
        this.birthday = birthday;
        this.city = city;
    }

    public Long getId() {
        return id;
    }

    public String getFirstname() {
        return firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public String getBirthday() {
        return birthday;
    }

    public String getCity() {
        return city;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public void setBirthday(String birthday) {
        this.birthday = birthday;
    }

    public void setCity(String city) {
        this.city = city;
    }
}
