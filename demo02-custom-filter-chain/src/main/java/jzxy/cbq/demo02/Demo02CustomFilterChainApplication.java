package jzxy.cbq.demo02;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo02CustomFilterChainApplication
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 21:08
 */
@SpringBootApplication
@Slf4j
public class Demo02CustomFilterChainApplication {
    public static void main(String[] args) {
        SpringApplication.run(Demo02CustomFilterChainApplication.class, args);

        log.info("Demo02CustomFilterChainApplication run successful ");
    }
}
