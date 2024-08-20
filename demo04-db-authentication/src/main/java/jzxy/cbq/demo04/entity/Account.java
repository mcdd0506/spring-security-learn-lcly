package jzxy.cbq.demo04.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import jzxy.cbq.common.entity.BaseData;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * Account
 *
 * @version 1.0.0
 * @author: mcdd
 * @date: 2024/8/20 23:58
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Account implements BaseData {
    /**
     * id
     */
    @TableId(type = IdType.AUTO)
    Integer id;
    /**
     * 用户名
     */
    String username;
    /**
     * 密码
     */
    String password;
    /**
     * 邮箱
     */
    String email;
    /**
     * 角色
     */
    String role;
    /**
     * 头像 link
     */
    String avatar;
    /**
     * 注册时间
     */
    Date registerTime;
}
