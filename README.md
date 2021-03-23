[toc]

# Spring Security

> `Spring Security` 是一个能够基于 Spring 的企业应用系统提供声明式的安全访问控制解决方案的安全框架。它提供了一组可以在 Spring 应用上下文中配置的 Bean，充分利用了 Spring 的 IoC（控制反转 Inversion of Control），DI（依赖注入：Dependency Injection）和 AOP（面向切面编程）功能，为应用系统提供声明式的安全访问控制功能，减少了为企业系统安全控制编写大量重复代码的工作

## Basic协议认证

通过`Http Basic`协议实现认证，实现方式：

* 在 Spring Boot 项目中引入`Spring Security`依赖：

  ```xml
  <!-- spring-boot 整合security -->
  <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
  </dependency>
  ```

* 添加 Spring Security 配置类，该配置类需要继承：`WebSecurityConfigurerAdapter`，重写其中的方法

  * 13行的方法主要配置用户账号信息和权限
  * 18行的方法配置认证的方式，此处指定为 http basic 协议方式
  
  ```java
  @Configuration
  @EnableWebSecurity
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
  
      /**
       * 添加授权账户
       * @param auth
       * @throws Exception
       */
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          // 设置用户账号信息和权限
          auth.inMemoryAuthentication().withUser("thomas_show").password("thomas").authorities("/");
          auth.inMemoryAuthentication().withUser("thomas_add").password("thomas").authorities("/");
      }
  
      @Override
      protected void configure(HttpSecurity http) throws Exception {
          // 配置 httpBasic HTTP协议认证
          http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();
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
  ```

* 重新启动项目，发送请求，弹出对话框，输入用户名及密码，认证成功后才允许访问服务中内容

  ![image-20210322141452921](https://gitee.com/TomStrong/picture-bed/raw/master/image-20210322141452921.png)

## FromLogin 表单认证

实现方式与上面的 Basic 认证基本相同，只需要修改 Spring Security 配置文件中对认证方式（上面代码中第18行配置）的配置：

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 配置 httpBasic HTTP协议认证
//        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();

        // 配置表单认证
        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().formLogin();
    }
```

重新启动项目后，再次发送请求，跳转到表单认证页面：

![image-20210322142518413](https://gitee.com/TomStrong/picture-bed/raw/master/image-20210322142518413.png)

### 用户授权

* 修改 Spring Security 配置文件（第18行方法），拦截所有的 http请求，在需要授权的方法前加上权限判断

  ```java
      @Override
      protected void configure(HttpSecurity http) throws Exception {
          // 配置 httpBasic HTTP协议认证
  //        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();
  
          // 配置表单认证
  //        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().formLogin();
  
          http.authorizeRequests()
                  .antMatchers("/addMember").hasAuthority("addMember")
                  .antMatchers("/delMember").hasAuthority("delMember")
                  .antMatchers("/updateMember").hasAuthority("updateMember")
                  .antMatchers("/showMember").hasAuthority("showMember")
  
                  .antMatchers("/**").fullyAuthenticated()
                  .and()
                  .formLogin();
      }
  ```

* 修改用户认证的方法（第11行方法），在每个用户的认证上加上各自的权限

  ```java
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          // 设置用户账号信息和权限
          auth.inMemoryAuthentication()
                  .withUser("thomas_show").password("thomas")
                  .authorities("addMember", "delMember", "updateMember", "showMember");
          auth.inMemoryAuthentication()
                  .withUser("thomas_add").password("thomas")
                  .authorities("showMember");
      }
  ```

若访问没有权限的方法，跳转到错误页面：

![image-20210322150026005](https://gitee.com/TomStrong/picture-bed/raw/master/image-20210322150026005.png)

### 错误页面配置

添加配置类，统一处理异常错误

```java
@Configuration
public class WebServerAutoConfiguration {

    @Bean
    public ConfigurableServletWebServerFactory webServerFactory() {
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();

        ErrorPage errorPage400 = new ErrorPage(HttpStatus.BAD_REQUEST, "/error/400");
        ErrorPage errorPage401 = new ErrorPage(HttpStatus.UNAUTHORIZED, "/error/401");
        ErrorPage errorPage403 = new ErrorPage(HttpStatus.FORBIDDEN, "/error/403");
        ErrorPage errorPage404 = new ErrorPage(HttpStatus.NOT_FOUND, "/error/404");
        ErrorPage errorPage415 = new ErrorPage(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "/error/415");
        ErrorPage errorPage500 = new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/error/500");

        factory.addErrorPages(errorPage400, errorPage401, errorPage403, errorPage404, errorPage415, errorPage500);

        return factory;
    }
}
```

当出现`FORBIDDEN`没有该授权错误时，跳转到请求`/error/402`进行处理。

编写错误处理请求接口：

```java
@RestController
public class ErrorController {

    @RequestMapping("/error/403")
    public String error() {
        return "您当前访问该接口权限不足，请稍后重试！";
    }
}
```

再次访问没有授权的请求，得到自定义的页面

![image-20210322150356107](https://gitee.com/TomStrong/picture-bed/raw/master/image-20210322150356107.png)

### 自定义登录页面

修改第18行配置，放行`login`请求，并且指定登录页面

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        // 配置 httpBasic HTTP协议认证
//        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();

        // 配置表单认证
//        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().formLogin();

        http.authorizeRequests()
                .antMatchers("/addMember").hasAuthority("addMember")
                .antMatchers("/delMember").hasAuthority("delMember")
                .antMatchers("/updateMember").hasAuthority("updateMember")
                .antMatchers("/showMember").hasAuthority("showMember")

//                .antMatchers("/**").fullyAuthenticated()
//                .and()
//                .formLogin();

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
```

## RBAC权限模型

数据库中表具体涉及五张表：

* `sys_permission`：权限表，具体包括字段有：**权限名**、**请求路径**
* `sys_role`：角色表，具体包括字段有：**角色名**、**角色描述**
* `sys_user`：用户表，具体包括字段有：**用户名**、**密码**（用作登录）
* `sys_role_permission`：角色和权限的多对多关系
* `sys_user_role`：用户和角色的关系

### 用户登录处理

在实际的项目中，用户的信息不应该写在内存中，而是在数据库中进行查找

用户的登录主要有两个逻辑步骤：

* 根据用户名查找到到用户
* 根据用户名级联查询到该用户对应的权限，封装到 security 中

编写实现代码，需要实现接口：`UserDetailsService`

```java
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
```

修改用户授权方式，即 Spring Security 配置类中的第11行方法

```java
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
```

另外，在上面的案例中，方法对应的权限也是写死在配置类中的，在开发中应该也是从数据库中获取数据，再封装到 security中，对代码进行优化：

```java
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
```

# JWT

> `JWT`：Json Web Token
>
> `Token`：令牌，临时生成一个密码，有一定有效期并且唯一

Token 和 SessionId 的思想是一样的，Session 存放在服务器端 JVM 内存中，Token存放在 redis 缓存中

解决分布式 Session 数据一致性的问题：Spring-Session，将 Session 中的内容缓存到 redis 中，而在分布式架构下，Token 完全解决了 Session 的痛点，基本上 Token 替代了 SessionId

## 传统 Token

* **登录**

> 在验证账号密码成功情况下，通过`UUID`生成一个令牌，将该令牌放入 redis 中，key为令牌，value 对应的存放的 userid。最终返回令牌给客户端，客户端将令牌存放到 cookie 中，每次请求都带有此令牌

* **验证会话信息**

> 在请求头中传递该令牌，从 redis 中验证该令牌是否在有效期内，获取 value 内容中的 userid，查询用户信息，返回给客户端



**缺点**：

1. 必须依赖服务器端，占用服务器资源
2. 效率非常低，每次验证需要从数据库中查询用户

**优点**：

1. 隐藏数据的真实性，安全系数非常高
2. 适用于分布式/微服务

## JWT

###  生成 JWT 令牌

编写一段 Java 代码，生成 JWT 令牌，观察 JWT 长什么样子

```java
public class CreateJWT {

    private static String SING_KEY = "thomas";

    public static void main(String[] args) {
        JwtBuilder jwtBuilder = Jwts.builder()
                .claim("phone", "18907124154")
                .signWith(SignatureAlgorithm.HS256, SING_KEY);

        System.out.println(jwtBuilder.compact());
    }
}
```

输出：

![image-20210323115934514](https://gitee.com/TomStrong/picture-bed/raw/master/image-20210323115934514.png)

可以将此 token 复制到  [JWT官网 ](https://jwt.io/#encoded-jwt)验证此 token

![image-20210323120401218](https://gitee.com/TomStrong/picture-bed/raw/master/image-20210323120401218.png)

JWT 就是对明文数据 base64 编码，通过解码可以直接获取到用户信息



**优点**：

1. 因为是 JSON 格式的 base64 编码，所以轻量、占用带宽小、可读性非常高
2. 数据存放在客户端，减轻服务器端的压力
3. 效率比传统 Token 验证高

**缺点**

1. JWT 一旦生成，无法修改
2. 无法销毁一个 JWT

### JWT 组成部分

> `JWT`由三个部分组成，以`.`隔开

JWT = Base64.Encoded ( Header + Payload ) + 签名值

#### Header

描述加密算法，上面生成 token 中的：*eyJhbGciOiJIUzI1NiJ9*

数据还是明文的，主要防止抓包篡改数据

HS256，属于验证签名

RSA256，属于非对称加密

#### Payload（载荷）

存放在 JWT 中的数据，需要注意敏感数据，不能存放，上面生成 token 中的：*eyJwaG9uZSI6IjE4OTA3MTI0MTU0In0*

#### 签名值

对 Payload 加上`SING_KEY`做 MD5 加密，即生成的 token 中的：*MONarhqL5PwS_oQShKlR38EvduhajAUfQ-WmzpK9RV0*

防止载荷中的内容是否被篡改

### 手写一个 JWT

根据对上面 JWT 的分析，可以手写出一个 JWT，代码如下：

```java
public class WriteJWT {

    private static final String SING_KEY = "thomas";

    public static void main(String[] args) {
        // 封装三个部分 header、payload、sign签名值

        // 定义 header
        JSONObject header = new JSONObject();
        header.put("alg", "HS256");

        String headerEncoded = Base64.getEncoder().encodeToString(header.toJSONString().getBytes());

        // 定义 payload
        JSONObject payload = new JSONObject();
        payload.put("phone", "18907124154");

        String payLoadJsonStr = payload.toJSONString();
        String payLoadEncoded = Base64.getEncoder().encodeToString(payLoadJsonStr.getBytes());

        // sign签名值
        String sign = DigestUtils.md5DigestAsHex((payload + SING_KEY).getBytes(StandardCharsets.UTF_8));

        
        String jwt = headerEncoded + "." + payLoadEncoded + "." + sign;

        System.out.println(jwt);
    }
}
```

签名验证，将 JWT 根据 “.” 分割，获取中间的 payload 部分，再加上签名进行 MD5 加密，跟签名进行比对：

```java
    // 验签
    String payLoadEncode = jwt.split("\\.")[1];
    String payLoadDecoder = new String(Base64.getDecoder().decode(payLoadEncode), "UTF-8");

    String newSign = DigestUtils.md5DigestAsHex((payLoadDecoder + SING_KEY).getBytes(StandardCharsets.UTF_8));
    System.out.println(newSign.equals(sign));
```

## 整合 Spring Security

关于 JWT 的一些操作，可以封装成工具类，基本代码相似，日后可重复使用

**在上面的 Spring Security 基本项目中，稍加改动，实现 JWT**

用户登录，在登录时通过了账号密码验证，需要把内容写入 JWT，将 JWT传递给客户端，编写一个 Filter，注意要实现`UsernamePasswordAuthenticationFilter`

```java
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
```

用户每访问一个资源，需要携带自身信息的 JWT 令牌，服务端将拦截此令牌，获取到其中的权限信息，同样编写一个 Filter，实现`BasicAuthenticationFilter`

```java
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
```

将这两个 filter 注册到 security 中，修改 Spring Security 的配置文件

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry = http.authorizeRequests();

        // 获取所有的权限信息
        List<PermissionEntity> allPermission = permissionMapper.findAllPermission();
        // 将权限封装到 security中
        allPermission.forEach(permissionEntity -> {
            urlRegistry.antMatchers(permissionEntity.getUrl()).hasAuthority(permissionEntity.getPermTag());
        });

        urlRegistry
                // 放行 login请求
                .antMatchers("/auth/login").permitAll()

                // /** 请求需要完全认证
                .antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilter(new JWTLoginFilter(authenticationManager()))
                .addFilter(new JWTValidationFilter(authenticationManager()))
                .csrf().disable()
                // 剔除 session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
```

通过以上的修改，实现了 Spring Security 整合 JWT 的认证方式