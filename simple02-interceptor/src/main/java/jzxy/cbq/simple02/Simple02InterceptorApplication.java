package jzxy.cbq.simple02;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Simple02InterceptorApplication
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 22:51
 */
@SpringBootApplication
@Slf4j
public class Simple02InterceptorApplication {
    public static void main(String[] args) {
        SpringApplication.run(Simple02InterceptorApplication.class, args);

        log.info("Simple02InterceptorApplication run successful ");
    }
}
