package jzxy.cbq.demo03;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo03MemoryAuthenticationApplication
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 23:46
 */
@SpringBootApplication
@Slf4j
public class Demo03MemoryAuthenticationApplication {
    public static void main(String[] args) {
        SpringApplication.run(Demo03MemoryAuthenticationApplication.class, args);

        log.info("Demo03MemoryAuthenticationApplication run successful ");
    }
}
