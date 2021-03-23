package org.thomas.utils.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * @program: security
 * @create: 2021-03-23 11:54
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: 测试 JWT
 **/
public class CreateJWT {

    private static String SING_KEY = "thomas";

    public static void main(String[] args) {
        JwtBuilder jwtBuilder = Jwts.builder()
                .claim("phone", "18907124154")
                .signWith(SignatureAlgorithm.HS256, SING_KEY);

        System.out.println(jwtBuilder.compact());
    }
}
