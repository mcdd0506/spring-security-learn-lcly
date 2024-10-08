package jzxy.cbq.demo04.config;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jzxy.cbq.common.entity.RestBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * SecurityConfiguration
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/25 09:50
 */
@Configuration
public class SecurityConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.
                        requestMatchers("/api/users/**").permitAll()
                        .requestMatchers("/api/auths/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form.
                        successHandler(this::onAuthenticationSuccess)
                        .failureHandler(this::onAuthenticationFailure))
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 设置响应头
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        // 构建返回数据
        UserDetails data = (UserDetails) authentication.getPrincipal();
        RestBean<String> success = RestBean.success(data.getUsername());
        // 返回
        writer.write(JSON.toJSONString(success));
    }

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // 设置响应头
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        // 构建返回数据
        String msg = exception.getMessage();
        RestBean<String> failure = RestBean.failure(HttpStatus.BAD_REQUEST.value(), msg);
        // 返回
        writer.write(JSON.toJSONString(failure));
    }
}
