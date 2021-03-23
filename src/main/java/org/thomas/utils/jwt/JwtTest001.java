package org.thomas.utils.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * @program: jwt
 * @create: 2021-03-23 16:35
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: 生成一个 JWT
 **/
public class JwtTest001 {

    private static final String SIGN_KEY = "thomas";

    public static void main(String[] args) {
        JwtBuilder jwtBuilder = Jwts.builder().claim("userImg", "用户头像")
                .signWith(SignatureAlgorithm.HS256, SIGN_KEY);
        System.out.println(jwtBuilder.compact());
    }
}
