package jzxy.cbq.simple02.config;

import jzxy.cbq.simple02.interceptor.HelloInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * WebMvcConfiguration
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 23:04
 */
@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        HelloInterceptor interceptor = new HelloInterceptor();
        registry.addInterceptor(interceptor).addPathPatterns("/api/hellos/*");
    }
}
