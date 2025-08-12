package com.democode.SecurityService.util;

import com.warrenstrange.googleauth.GoogleAuthenticator;

public class TotpUtil {
    private static final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public static boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}