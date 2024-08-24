# Spring Security 的用户认证

> [!NOTE] 内容
>
> - 用户认证信息以及信息来源
> - 基于内存进行认证
> - 基于 DB 数据库进行认证
> - 密码升级以及 JSON 格式返回结果

# 一、认证信息及其来源

> 通常地在进行安全设计的时候我们总是围绕以下两点：
> - 需要认证的用户需要有什么属性
> - 相关属性来源

下面我们介绍 Spring Security 是如何进行设计的

## 1.1 用户的认证信息

用户的认证信息即用户属性中涉及到 Spring Security 安全检查需要用到的属性，通常包括：

- 用户名
- 密码
- 用户权限列表
- 账号状态 (是否锁定、是否过期)
- 证书状态

Spring Security 提供了一个 UserDetails 接口，用来保存用户的认证和授权方面的信息

```java
public interface UserDetails extends Serializable {
    
	Collection<? extends GrantedAuthority> getAuthorities();
	String getPassword();
	String getUsername();
	boolean isAccountNonExpired();
	boolean isAccountNonLocked();
	boolean isCredentialsNonExpired();
	boolean isEnabled();

}

```

其中 `GrantedAuthority` 代码如下

```java
public interface GrantedAuthority extends Serializable {
	String getAuthority();
}
```

Spring Security 中对 `UserDetails` 接口的其中一个实现为：

```java
public class User implements UserDetails, CredentialsContainer {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private static final Log logger = LogFactory.getLog(User.class);

	private String password;

	private final String username;

	private final Set<GrantedAuthority> authorities;

	private final boolean accountNonExpired;

	private final boolean accountNonLocked;

	private final boolean credentialsNonExpired;

	private final boolean enabled;

}
    
```


## 1.2 认证信息的来源

认证信息的来源指的是用户信息的存储位置通常包括:

- 内存（InMemory）
- 数据库（JDBC）

Spring Security 支持不同的用户信息来源，Spring Security 对其均有对应的处理类（该处理类都实现了 `UserDetailsManager` 接口）其部分代码如下：

```java
public interface UserDetailsManager extends UserDetailsService {

	/**
	 * Create a new user with the supplied details.
	 */
	void createUser(UserDetails user);

	/**
	 * Update the specified user.
	 */
	void updateUser(UserDetails user);

	/**
	 * Remove the user with the given login name from the system.
	 */
	void deleteUser(String username);

	/**
	 * Modify the current user's password. This should change the user's password in the
	 * persistent user repository (database, LDAP etc).
	 * @param oldPassword current password (for re-authentication if required)
	 * @param newPassword the password to change to
	 */
	void changePassword(String oldPassword, String newPassword);

	/**
	 * Check if a user with the supplied login name exists in the system.
	 */
	boolean userExists(String username);

}
```

该接口主要是对 `UserDetailsService` 进行拓展其实现类有：

- `InMemoryUserDetailsManager`
- `JdbcUserDetailsManager`

![image-20240824153413533](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408242334991.png)

其中 `UserDetailsService` 部分代码如下：

```java
public interface UserDetailsService {
    
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

}
```

# 二、基于内存进行认证

> [!NOTE] 内容
>
> - 通过配置文件
> - 通过手动配置
> - Spring Security 的密码加密器

## 2.1 通过配置文件

前面我们[通过在配置文件 （application.yaml）中配置的用户进行自定义用户信息的配置](./demo01.md#四、快速入门)，其实该过程就是基于内存进行验证的，我们可以通过 DEBUG 进行验证
首先我们需要确保配置文件中存在如下类似配置：

```yaml
server:
  port: 8082
spring:
  security:
    user:
      name: root
      password: root
```

然后我们通过查看 `UserDetailsServiceAutoConfiguration` 相关代码为其设置断点：

```java
	@Bean
	public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
			ObjectProvider<PasswordEncoder> passwordEncoder) {
		SecurityProperties.User user = properties.getUser();
		List<String> roles = user.getRoles();
		return new InMemoryUserDetailsManager(User.withUsername(user.getName()) // 设置断点
			.password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
			.roles(StringUtils.toStringArray(roles))
			.build());
	}
```

然后我们通过对 `InMemoryUserDetailsManager` 的构造其设置断点：

```java
	public InMemoryUserDetailsManager(UserDetails... users) {
		for (UserDetails user : users) { // 设置断点
			createUser(user);
		}
	}
```

然后我们启动 DEBUG 调试可以看到应用程序执行流程为：

![image-20240824150903768](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408242309371.png)

![image-20240824150933488](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408242309766.png)

注意到 Spring Security 自动为我们的密码添加了一个前缀 `{noop}` 其代表该密码不采用加密措施处理（默认情况下 Spring Security 不支持明文存储密码）

## 2.2 通过手动配置

接下来我们通过手动配置的方式实现基于内存进行认证，其实现思路为通过在配置类中手动声明 `InMemoryUserDetailsManager` Bean 从而覆盖 Spring Security 的默认配置，然后仿照 `UserDetailsServiceAutoConfiguration` 
中创建用户的方式进行编码即可，其参考代码如下：

```java
	@Bean
	public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
			ObjectProvider<PasswordEncoder> passwordEncoder) {
		SecurityProperties.User user = properties.getUser();
		List<String> roles = user.getRoles();
		return new InMemoryUserDetailsManager(User.withUsername(user.getName())
			.password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
			.roles(StringUtils.toStringArray(roles))
			.build());
	}
```
其主要是通过 `User.withUsername().password().roles().build()` 的方式进行用户的创建，因此我们可以通过：

1. 创建配置类并手动声明 `InMemoryUserDetailsManager` Bean

```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        // 自定义用户创建逻辑
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.
                        requestMatchers("/api/users/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
```

2. 通过 `User.withUsername().password().roles().build()` 的方式实现自定义用户创建逻辑

```java
    @Bean
public InMemoryUserDetailsManager userDetailsManager() {
    UserDetails user = User.withUsername("user")
            .password("123456")
            .roles("USER")
            .build();
    return new InMemoryUserDetailsManager(user);
}
```

然后我们访问 `localhost:8082/login` 页面进行下面测试：

- root + root （预期应为错误，因为我们自定义了相关验证逻辑）
- user + 123456 （预期应为正确）

![image-20240824152632864](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408242326991.png)

但是当我们通过 user + 123456 访问的时候程序却报错：

```shell
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
```

但这确实说明我们的自定义用户逻辑已经生效了，至于报错原因还记得我们上面提及过得默认情况下 Spring Security 不支持明文密码的处理，我们需要为其添加 `{noop}` 前缀

```java
    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        UserDetails user = User.withUsername("user")
                .password("{noop}123456") // [!code ++]
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
```

![image-20240824153119275](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408242331551.png)

## 2.3 Spring Security 的密码加密器

上面我们遇到了 `java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"` 报错原因是我们在没有配置 `{noop}` 的时候 Spring Security 提示我们密码加密器为空（PasswordEncoder is null），此处的密码加密器在 Spring Security 中是通过 `PasswordEncoder` 接口完成的：

```java
public interface PasswordEncoder {

	/**
	 * Encode the raw password. Generally, a good encoding algorithm applies a SHA-1 or
	 * greater hash combined with an 8-byte or greater randomly generated salt.
	 */
	String encode(CharSequence rawPassword);

	/**
	 * Verify the encoded password obtained from storage matches the submitted raw
	 * password after it too is encoded. Returns true if the passwords match, false if
	 * they do not. The stored password itself is never decoded.
	 * @param rawPassword the raw password to encode and match
	 * @param encodedPassword the encoded password from storage to compare with
	 * @return true if the raw password, after encoding, matches the encoded password from
	 * storage
	 */
	boolean matches(CharSequence rawPassword, String encodedPassword);

	/**
	 * Returns true if the encoded password should be encoded again for better security,
	 * else false. The default implementation always returns false.
	 * @param encodedPassword the encoded password to check
	 * @return true if the encoded password should be encoded again for better security,
	 * else false.
	 */
	default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}

}
```

其实现类主要有：

<img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408242348814.png" alt="image-20240824154757305" style="zoom:67%;" />

其中：

- `NoOpPasswordEncoder` 代表不加密我们可以通过以下代码进行验证：

```java
    @Test
    void noOpEncoderTest(){
        String source = "123456";
        PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
        System.out.println(encoder.encode(source));
    }
```

![image-20240824161607680](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408250016919.png)

上面我们提及过的 `{noop}` 实际上就是该类截取 `PasswordEncoder` 后剩下的 `NoOp` 代表不加密

- `BCryptPasswordEncoder`

该密码加密器为 Spring Security 官方推荐因为其有以下优点：

1. 区别于其它加密算法（如 SHA-256），该算法无需单独处理 salt （盐）其 salt 由随机数生成器产生
2. 该算法拥有缓存在并发场景下效率高

```java
    @Test
    void bCryptEncoderTest(){
        String source = "123456";
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        String first = encoder.encode(source);
        System.out.println("第一次加密: " + first);
        assertTrue(encoder.matches(source, first),"第一次密码匹配错误");
        String second = encoder.encode(source);
        System.out.println("第二次加密: " + second);
        assertTrue(encoder.matches(source, first),"第二次密码匹配错误");

    }
```

![image-20240824162106751](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408250021963.png)

可以看到即使多次加密其加密后的密码是不同的 （随机数生成器 --> salt）但仍旧可以匹配成功

- `DelegatingPasswordEncoder`

该密码加密器为 Spring Security 默认加密器，其可以自动匹配不同加密器，匹配规则如下：

- `{noop}` 匹配 NoOpPasswordEncoder
- `{bcrypt}` 匹配 BCryptPasswordEncoder

如果需要自定义密码加密器只需要在 Spring Security 中创建一个相关的 Bean 即可，例如创建一个 `BCryptPasswordEncoder` :

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

> [!CAUTION] 注意
>
> 如果应用程序中的加密器不是 `DelegatingPasswordEncoder` 则无法使用前缀进行匹配

# 三、基于 DB 数据库进行认证



# 四、密码升级以及 JSON 格式返回结果

