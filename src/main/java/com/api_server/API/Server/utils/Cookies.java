package com.api_server.API.Server.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Utility class for managing cookies in HTTP responses.
 * Provides methods to set and delete cookies, including secure and HTTP-only attributes.
 */
@Component
public class Cookies {

    @Value("${token.access.expiration.minutes}")
    private int accessTokenExpirationMinutes;

    @Value("${token.refresh.expiration.days}")
    private int refreshTokenExpirationDays;

    public void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        setCookie(response, "accessToken", accessToken,
                (int) Duration.ofMinutes(accessTokenExpirationMinutes).getSeconds());
        setCookie(response, "refreshToken", refreshToken,
                (int) Duration.ofDays(refreshTokenExpirationDays).getSeconds());
    }

    /**
     * Deletes the access token and refresh token cookies by setting their values to null and max age to 0.
     *
     * @param response the HTTP response from which the cookies will be removed
     */
    public void deleteCookie(HttpServletResponse response) {
        setCookie(response, "accessToken", null, 0);
        setCookie(response, "refreshToken", null, 0);
    }

    /**
     * Helper method to create and add a cookie to the HTTP response.
     * The cookie is configured with secure, HTTP-only, and SameSite attributes.
     *
     * @param response the HTTP response to which the cookie will be added
     * @param name the name of the cookie
     * @param value the value of the cookie; can be null to delete the cookie
     * @param maxAge the maximum age of the cookie in seconds
     */
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