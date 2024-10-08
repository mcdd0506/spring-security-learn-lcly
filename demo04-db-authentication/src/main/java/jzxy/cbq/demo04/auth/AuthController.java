package jzxy.cbq.demo04.auth;


import jzxy.cbq.common.entity.RestBean;
import jzxy.cbq.common.utils.Const;
import jzxy.cbq.demo04.entity.Account;
import jzxy.cbq.demo04.service.AccountService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AuthController
 *
 * @author: mcdd
 * @date: 2024/8/25 11:51
 * @since 1.0.0
 */
@RestController
@RequestMapping("/api/auths")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AccountService service;

    @PostMapping("/register")
    private RestBean<RegisterVo> register(@RequestBody RegisterVo registerVo) throws UserNameAlreadyExistException {
        System.out.println("registerVo = " + registerVo);
        try {
            if (service.register(registerVo)) {
                return RestBean.success();
            }
        } catch (UserNameAlreadyExistException e) {
            if (log.isErrorEnabled()) {
                log.error(e.getMessage());
            }
            return RestBean.failure(HttpStatus.BAD_REQUEST.value(), e.getMessage());
        }
        return RestBean.failure(HttpStatus.BAD_REQUEST.value(), Const.DEFAULT_INNER_ERROR_MSG);
    }
}
