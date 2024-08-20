package jzxy.cbq.simple02.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HelloController
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 22:45
 */
@RestController
@RequestMapping("/api/hellos")
public class HelloController {

    @GetMapping("/{name}")
    public String sayHello(@PathVariable("name") String name) {
        return "Hello " + name;
    }
}
