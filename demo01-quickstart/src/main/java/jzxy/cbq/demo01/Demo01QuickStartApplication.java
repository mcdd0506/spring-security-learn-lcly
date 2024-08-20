package jzxy.cbq.demo01;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo01QuickStartApplication
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 12:56
 */
@SpringBootApplication
@Slf4j
public class Demo01QuickStartApplication {
    public static void main(String[] args) {
        SpringApplication.run(Demo01QuickStartApplication.class, args);
        log.info("Demo01QuickStartApplication run successful ");
    }
}
