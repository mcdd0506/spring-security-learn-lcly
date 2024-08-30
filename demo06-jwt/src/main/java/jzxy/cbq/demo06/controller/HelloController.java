package jzxy.cbq.demo06.controller;

import jzxy.cbq.common.entity.RestBean;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HelloController
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/30 15:01
 */
@RestController
@RequestMapping("/api/hellos")
@Slf4j
public class HelloController {
    @GetMapping("/sayHello")
    public RestBean<String> sayHello() {
        return RestBean.success("hello");
    }
}
