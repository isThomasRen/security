package com.thomas;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.thomas.mapper")
public class AppSecurity {
    public static void main(String[] args) {
        SpringApplication.run(AppSecurity.class);
    }
}
