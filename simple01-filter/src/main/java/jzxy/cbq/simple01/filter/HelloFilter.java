package jzxy.cbq.simple01.filter;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.Objects;

/**
 * HelloFilter
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 22:55
 */
@WebFilter(urlPatterns = "/api/hellos/*")
@Slf4j
public class HelloFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        String ip = req.getRemoteAddr();
        HttpSession session = req.getSession();
        Integer count = (Integer) session.getAttribute("count");
        count = Objects.isNull(count) ? 1 : ++count;
        log.info("HelloFilter --> ip: {} count: {}", ip, count);
        session.setAttribute("count", count);


        chain.doFilter(request, response);
    }
}
