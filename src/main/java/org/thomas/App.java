package org.thomas;


import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @program: jwt
 * @create: 2021-03-23 16:19
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: 服务启动类
 **/
@SpringBootApplication
@MapperScan(basePackages = "org.thomas.mapper")
public class App {

    public static void main(String[] args) {
        SpringApplication.run(App.class);
    }
}
