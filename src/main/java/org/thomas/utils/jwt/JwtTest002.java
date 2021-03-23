package org.thomas.utils.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * @program: jwt
 * @create: 2021-03-23 16:40
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: JWT 解密
 **/
public class JwtTest002 {

    private static final String SIGN_KEY = "thomas";

    public static void main(String[] args) {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySW1nIjoi55So5oi35aS05YOPIn0.5lu7_TBEEjzM6d_qw8AmNr3wScpwiR-fd8zHTYTjMCk";
        Claims body = Jwts.parser().setSigningKey(SIGN_KEY).parseClaimsJws(jwt).getBody();
        System.out.println(body.get("userImg"));
    }
}
