package jzxy.cbq.demo05.service;

import jzxy.cbq.common.entity.RestBean;
import jzxy.cbq.demo05.entity.LoginVo;

/**
 * AuthService
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/28 20:58
 */
public interface AuthService {
    RestBean<String> login(LoginVo vo);
}
