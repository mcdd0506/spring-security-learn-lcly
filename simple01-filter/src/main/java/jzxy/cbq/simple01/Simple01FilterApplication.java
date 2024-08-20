package jzxy.cbq.simple01;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Simple01FilterApplication
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 22:43
 */
@SpringBootApplication
@Slf4j
public class Simple01FilterApplication {
    public static void main(String[] args) {
        SpringApplication.run(Simple01FilterApplication.class, args);

        log.info("Simple01FilterApplication run successful ");
    }
}
