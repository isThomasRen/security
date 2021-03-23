package com.thomas.config;

import com.thomas.entity.PermissionEntity;
import com.thomas.mapper.PermissionMapper;
import com.thomas.service.MemberUserDetailService;
import com.thomas.utils.MD5Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

/**
 * @program: security
 * @create: 2021-03-22 13:49
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: Spring Security配置类
 **/
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MemberUserDetailService userDetailService;

    @Autowired
    private PermissionMapper permissionMapper;

    /**
     * 添加授权账户
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 内存方式：设置用户账号信息和权限
//        auth.inMemoryAuthentication()
//                .withUser("thomas_show").password("thomas")
//                .authorities("addMember", "delMember", "updateMember", "showMember");
//        auth.inMemoryAuthentication()
//                .withUser("thomas_add").password("thomas")
//                .authorities("showMember");

        auth.userDetailsService(userDetailService).passwordEncoder(new PasswordEncoder() {
            /**
             * 对密码 MD5加密
             * @param charSequence
             * @return
             */
            @Override
            public String encode(CharSequence charSequence) {
                return MD5Util.encode((String) charSequence);
            }

            /**
             * @param charSequence  用户输入的密码
             * @param s 数据库字段中加密好的密码
             * @return
             */
            @Override
            public boolean matches(CharSequence charSequence, String s) {
                String encode = MD5Util.encode((String) charSequence);
                boolean result = encode.equals(s);
                return result;
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 配置 httpBasic HTTP协议认证
//        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();

        // 配置表单认证
//        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().formLogin();

        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry = http.authorizeRequests();

        // 获取所有的权限信息
        List<PermissionEntity> allPermission = permissionMapper.findAllPermission();
        // 将权限封装到 security中
        allPermission.forEach(permissionEntity -> {
            urlRegistry.antMatchers(permissionEntity.getUrl()).hasAuthority(permissionEntity.getPermTag());
        });

//        urlRegistry
//                .antMatchers("/addMember").hasAuthority("addMember")
//                .antMatchers("/delMember").hasAuthority("delMember")
//                .antMatchers("/updateMember").hasAuthority("updateMember")
//                .antMatchers("/showMember").hasAuthority("showMember")

//                .antMatchers("/**").fullyAuthenticated()
//                .and()
//                .formLogin();

        urlRegistry
                // 放行 login请求
                .antMatchers("/login").permitAll()

                // /** 请求需要完全认证
                .antMatchers("/**").fullyAuthenticated()
                .and()
                // 登录方式为表单，并且指定 login页面
                .formLogin().loginPage("/login")

                .and()
                .csrf().disable();
    }

    /**
     * There is no PasswordEncoder mapped for the id "null"
     * 原因：升级为 Security5.0以上密码支持多种加密方式，若不配加密方式，报上述错误
     * @return 添加这个 Bean，回复到以前的模式
     */
    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }
}
