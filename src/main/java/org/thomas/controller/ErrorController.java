package org.thomas.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName ErrorController
 * @Author 蚂蚁课堂余胜军 QQ644064779 www.mayikt.com
 * @Version V1.0
 **/
@RestController
public class ErrorController {
    @RequestMapping("/error/403")
    public String error403() {
        return "您当前访问的接口权限不足.";
    }
}
