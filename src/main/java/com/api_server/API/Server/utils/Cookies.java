package com.api_server.API.Server.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import java.time.Duration;

public class Cookies {
    public static void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        setCookie(response, "accessToken", accessToken, (int) Duration.ofMinutes(15).getSeconds());
        setCookie(response, "refreshToken", refreshToken, (int) Duration.ofDays(30).getSeconds());
    }

    public static void deleteCookie(HttpServletResponse response) {
        setCookie(response, "accessToken", null, 0);
        setCookie(response, "refreshToken", null, 0);
    }

    private static void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setMaxAge(maxAge);
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
    }
}
