package jzxy.cbq.demo05.controller;

import jzxy.cbq.common.entity.RestBean;
import jzxy.cbq.demo05.entity.LoginVo;
import jzxy.cbq.demo05.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

/**
 * AuthController
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/28 21:05
 */
@RestController
@RequestMapping("/api/auths")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService service;

    @CrossOrigin
    @PostMapping("/login")
    public RestBean<String> login(@RequestBody LoginVo vo){
         return service.login(vo);
    }
}
