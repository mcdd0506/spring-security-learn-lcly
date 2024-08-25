package jzxy.cbq.demo04.exception;


import jzxy.cbq.common.entity.RestBean;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * AuthException
 *
 * @author: mcdd
 * @date: 2024/8/25 11:26
 * @since 1.0.0
 */
@RestControllerAdvice
public class AuthException {


    @ExceptionHandler(UsernameNotFoundException.class)
    private RestBean<String> userNameAlreadyExistException(){
        return RestBean.failure(HttpStatus.BAD_REQUEST.value(), "用户名或邮箱已被注册");
    }

}
