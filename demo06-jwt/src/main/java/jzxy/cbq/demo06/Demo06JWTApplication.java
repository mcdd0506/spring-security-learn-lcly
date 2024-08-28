package jzxy.cbq.demo06;

import lombok.extern.slf4j.Slf4j;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo06JWTApplication
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/28 23:21
 */
@SpringBootApplication
@MapperScan("jzxy.cbq.demo06.mapper")
@Slf4j
public class Demo06JWTApplication {
    public static void main(String[] args) {
        SpringApplication.run(Demo06JWTApplication.class, args);

        log.info("Demo06JWTApplication run successful ");
    }
}
