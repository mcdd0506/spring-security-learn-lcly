package jzxy.cbq.demo05.service.impl;

import jzxy.cbq.common.entity.RestBean;
import jzxy.cbq.demo05.entity.LoginVo;
import jzxy.cbq.demo05.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * AuthServiceImpl
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/28 20:59
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;

    @Override
    public RestBean<String> login(LoginVo vo) {
        // 获取 username 和 password 并将其封装为
        String username = vo.getUsername();
        String password = vo.getPassword();
        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
                password);
        // 发起认证
        try {
            Authentication authentication = authenticationManager.authenticate(authRequest);
            if (authentication.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
                return RestBean.success("认证成功");
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
        }
        return RestBean.unauthorized("认证失败");
    }
}
