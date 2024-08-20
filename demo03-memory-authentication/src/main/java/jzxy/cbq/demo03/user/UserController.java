package jzxy.cbq.demo03.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * UserController
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 16:28
 */
@Controller
@RequestMapping("/api/users")
public class UserController {

    @ResponseBody
    @GetMapping("/sayHello")
    public String sayHello() {
        return "hello";
    }
}
