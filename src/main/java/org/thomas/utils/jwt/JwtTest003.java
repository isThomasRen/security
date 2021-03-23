package org.thomas.utils.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

/**
 * @program: jwt
 * @create: 2021-03-23 16:45
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: 设置超时时间
 **/
public class JwtTest003 {

    private static final String SIGN_KEY = "thomas";

    public static void main(String[] args) {
        // 当前时间
        long now = System.currentTimeMillis();

        // 过期时间
        long exp = now + 1000 * 3;

        JwtBuilder builder = Jwts.builder()
                .setIssuedAt(new Date())
                .claim("userId", "12345")
                .signWith(SignatureAlgorithm.HS256, SIGN_KEY)
                .setExpiration(new Date(exp));

        System.out.println(builder.compact());

        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Claims body = Jwts.parser().setSigningKey(SIGN_KEY).parseClaimsJws(builder.compact()).getBody();
        System.out.println(body);
    }
}
