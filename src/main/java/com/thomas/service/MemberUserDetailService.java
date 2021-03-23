package com.thomas.service;

import com.thomas.entity.PermissionEntity;
import com.thomas.entity.UserEntity;
import com.thomas.mapper.UserMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @program: security
 * @create: 2021-03-22 15:30
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: 用户细节认证
 **/
@Service
@Slf4j
public class MemberUserDetailService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. 根据该用户名称查询在数据库中是否存在
        UserEntity user = userMapper.findByUsername(username);
        if (user == null) {
            return null;
        }

        // 2. 需要级联查询对应用户的权限
        List<PermissionEntity> permissionByUsername = userMapper.findPermissionByUsername(username);
        List<GrantedAuthority> authorities = new ArrayList<>();
        permissionByUsername.forEach(permissionEntity -> authorities.add(new SimpleGrantedAuthority(permissionEntity.getPermTag())));

        // 3. 将该权限添加到 security
        user.setAuthorities(authorities);
        return user;
    }
}
