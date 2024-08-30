package jzxy.cbq.demo06.filter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jzxy.cbq.common.utils.JWTUtils;
import jzxy.cbq.demo06.entity.AuthEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * TokenCheckFilter
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/30 14:45
 */
@Component
@RequiredArgsConstructor
public class TokenCheckFilter extends OncePerRequestFilter {
    private final RedisTemplate<String,Object> redisTemplate;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization");
        String uri = request.getRequestURI();
        // 放行 login 请求
        if (uri.startsWith("/api/auths")) {
            filterChain.doFilter(request, response);
            return;
        }
        // 获取请求头中的 token
        if (ObjectUtils.isEmpty(token)) {
            throw new RuntimeException("Access token is empty");
        }
        String subject;
        try {
            Claims claims = JWTUtils.verifyToken(token);
            subject = claims.getSubject();
        }catch (Exception e) {
            throw new RuntimeException("Access token fail", e);
        }
        // 从 redis 中通过用户标识获取认证信息
        AuthEntity entity = (AuthEntity) redisTemplate.opsForValue().get(subject);
        if (ObjectUtils.isEmpty(entity)) {
            throw new ServletException("Access token is empty in redis");
        }
        Authentication authentication = new UsernamePasswordAuthenticationToken(entity, null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
