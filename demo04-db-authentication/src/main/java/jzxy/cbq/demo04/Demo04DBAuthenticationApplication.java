package jzxy.cbq.demo04;

import lombok.extern.slf4j.Slf4j;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo04DBAuthenticationApplication
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 23:46
 */
@SpringBootApplication
@MapperScan("jzxy.cbq.demo04.mapper")
@Slf4j
public class Demo04DBAuthenticationApplication {
    public static void main(String[] args) {
        SpringApplication.run(Demo04DBAuthenticationApplication.class, args);

        log.info("Demo04DBAuthenticationApplication run successful ");
    }
}
