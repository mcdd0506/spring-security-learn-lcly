package jzxy.cbq.demo06.auth;


import lombok.Data;

/**
 * RegisterVo
 *
 * @author: mcdd
 * @date: 2024/8/25 11:52
 * @since 1.0.0
 */
@Data
public class RegisterVo {
    private String username;
    private String password;
    private String email;
}
