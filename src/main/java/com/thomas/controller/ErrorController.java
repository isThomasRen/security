package com.thomas.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ErrorController {

    @RequestMapping("/error/403")
    public String error() {
        return "您当前访问该接口权限不足，请稍后重试！";
    }
}
