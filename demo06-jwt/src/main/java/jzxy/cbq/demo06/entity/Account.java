package jzxy.cbq.demo06.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import jzxy.cbq.common.entity.BaseData;
import jzxy.cbq.common.utils.Const;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
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
public class Account implements BaseData, Serializable {
    /**
     * id
     */
    @TableId(type = IdType.AUTO)
    private Integer id;
    /**
     * 用户名
     */
    private String username;
    /**
     * 密码
     */
    private String password;
    /**
     * 邮箱
     */
    private String email;
    /**
     * 角色
     */
    private String role = Const.ROLE_NORMAL;
    /**
     * 头像 link
     */
    private String avatar = Const.DEFAULT_AVATAR;
    /**
     * 注册时间
     */
    private Date registerTime = new Date();

    public Account(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }
}
