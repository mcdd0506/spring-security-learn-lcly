package jzxy.cbq.demo06.service.impl;

import jzxy.cbq.common.entity.RestBean;
import jzxy.cbq.common.utils.JWTUtils;
import jzxy.cbq.demo06.entity.AuthEntity;
import jzxy.cbq.demo06.entity.LoginVo;
import jzxy.cbq.demo06.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * AuthServiceImpl
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/30 14:26
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final RedisTemplate<String,Object> redisTemplate;

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
                // 生成 token
                String subject = "login:" + ((AuthEntity) authentication.getPrincipal()).getAccount().getId();
                String token = JWTUtils.generateToken(subject);
                redisTemplate.opsForValue().set(subject , authentication.getPrincipal(),30, TimeUnit.MINUTES);
                return RestBean.success(token);
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
        }
        return RestBean.unauthorized("认证失败");
    }
}
