package com.projects.auth.service;

import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CookieService {

    public Cookie generateCookie(String name,String value,int exp){
        Cookie cookie = new Cookie(name,value);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(exp);
        return cookie;
    }
}

