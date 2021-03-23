package org.thomas.filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.thomas.utils.JwtUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * @program: jwt
 * @create: 2021-03-23 17:25
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: 验证 JWT
 **/
public class JWTValidationFilter extends BasicAuthenticationFilter {

    public JWTValidationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /**
     * 拦截请求
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = request.getHeader("token");
        // jwt验证
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(token));
        super.doFilterInternal(request, response, chain);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String token) {
        String username = JwtUtils.getUsername(token);

        if (!StringUtils.isEmpty(username)) {
            // 解析权限列表
            List<SimpleGrantedAuthority> userRole = JwtUtils.getUserRole(token);
            return new UsernamePasswordAuthenticationToken(username, null, userRole);
        }
        return null;
    }
}
