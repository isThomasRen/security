package org.thomas.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.thomas.entity.UserEntity;
import org.thomas.utils.JwtUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * @program: jwt
 * @create: 2021-03-23 17:12
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description:
 **/
public class JWTLoginFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * 获取权限管理
     */
    private AuthenticationManager authenticationManager;

    public JWTLoginFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;

        /**
         * 后端登录接口
         */
        super.setFilterProcessesUrl("/auth/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 调用 MemberUserDetailService 账号密码登录
        try {
            UserEntity userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            userEntity.getUsername(),
                            userEntity.getPassword(),
                            userEntity.getAuthorities()
                    )
            );

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用户账号密码验证成功
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // 账号密码验证成功，再响应头中响应 jwt
        UserEntity principal = (UserEntity) authResult.getPrincipal();
        String jwtToken = JwtUtils.generateJsonWebToken(principal);
        response.addHeader("token", jwtToken);
    }

    /**
     * 用户账号密码验证失败
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }
}
