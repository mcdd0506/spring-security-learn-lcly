package jzxy.cbq.demo06.service;

import jzxy.cbq.common.entity.RestBean;
import jzxy.cbq.demo06.entity.LoginVo;

/**
 * AuthService
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/30 14:26
 */
public interface AuthService{
    RestBean<String> login(LoginVo vo);
}
