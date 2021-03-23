package org.thomas.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @ClassName LoginController
 * @Author 蚂蚁课堂余胜军 QQ644064779 www.mayikt.com
 * @Version V1.0
 **/
@Controller
public class LoginController {
    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
