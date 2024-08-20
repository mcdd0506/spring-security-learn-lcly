package jzxy.cbq.simple02.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Objects;

/**
 * HelloInterceptor
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 23:05
 */
@Slf4j
public class HelloInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        String ip = request.getRemoteAddr();
        HttpSession session = request.getSession();
        Integer count = (Integer) session.getAttribute("count");
        count = Objects.isNull(count) ? 1 : ++count;
        log.info("HelloInterceptor --> ip: {} count: {}", ip, count);
        session.setAttribute("count", count);

        return true;
    }
}
