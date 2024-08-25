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

> [!CAUTION] 注意
>
> 首先我们需要明确一个问题，在上面我们提到 Spring Security 提供了 InMemory 和 JDBC 两种基于 `UserDetailsService` 的实现，我们需要注意在基于 JDBC 的实现中， Spring Security  使用的 JDBC Template 进行数据库相关操作，因此其默认实现并不适用于 MyBatis、MyBatisPlus 等 ORM 框架
>
> ![image-20240825015747873](/home/mcdd/Pictures/typora/image-20240825015747873.png)

那么我们如何使用自定义的 ORM 实现基于 DB 数据库进行认证呢？我们需要梳理 Spring Security  表单登录认证流程：

1. 表单请求被 `UsernamePasswordAuthenticationFilter` 捕获后调用 `attemptAuthentication` 方法将用户名和密码封装到 `UsernamePasswordAuthenticationToken` 对象中

```java
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
        // 1. 获取 POST 请求表单中的 `username` 和 `password` // [!code ++]
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
		String username = obtainUsername(request);
		username = (username != null) ? username.trim() : "";
		String password = obtainPassword(request);
		password = (password != null) ? password : "";
        // 2. 将获取到的 `username` 和 `password` 封装为 UsernamePasswordAuthenticationToken // [!code ++]
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
				password);
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
        // 3. 调用 AuthenticationManager 的 authenticate 方法发起认证 // [!code ++]
		return this.getAuthenticationManager().authenticate(authRequest);
	}
```

2. `AuthenticationManager` 认证管理器通过 `authenticate` 方法发起认证之后由 `ProviderManager` 根据参数类型匹配相应的 `AuthenticationProvider`


```java
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Class<? extends Authentication> toTest = authentication.getClass();
		AuthenticationException lastException = null;
		AuthenticationException parentException = null;
		Authentication result = null;
		Authentication parentResult = null;
		int currentPosition = 0;
		int size = this.providers.size();
		for (AuthenticationProvider provider : getProviders()) {
			if (!provider.supports(toTest)) { // 1. 据参数类型匹配相应的 `AuthenticationProvider` // [!code ++]
				continue;
			}
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Authenticating request with %s (%d/%d)",
						provider.getClass().getSimpleName(), ++currentPosition, size));
			}
			try {
				result = provider.authenticate(authentication);
				if (result != null) {
					copyDetails(authentication, result);
					break;
				}
			}
			catch (AccountStatusException | InternalAuthenticationServiceException ex) {
				prepareException(ex, authentication);
				// SEC-546: Avoid polling additional providers if auth failure is due to
				// invalid account status
				throw ex;
			}
			catch (AuthenticationException ex) {
				lastException = ex;
			}
		}
		if (result == null && this.parent != null) {
			// Allow the parent to try.
			try {
				parentResult = this.parent.authenticate(authentication);
				result = parentResult;
			}
			catch (ProviderNotFoundException ex) {
				// ignore as we will throw below if no other exception occurred prior to
				// calling parent and the parent
				// may throw ProviderNotFound even though a provider in the child already
				// handled the request
			}
			catch (AuthenticationException ex) {
				parentException = ex;
				lastException = ex;
			}
		}
		if (result != null) {
			if (this.eraseCredentialsAfterAuthentication && (result instanceof CredentialsContainer)) {
				// Authentication is complete. Remove credentials and other secret data
				// from authentication
				((CredentialsContainer) result).eraseCredentials();
			}
			// If the parent AuthenticationManager was attempted and successful then it
			// will publish an AuthenticationSuccessEvent
			// This check prevents a duplicate AuthenticationSuccessEvent if the parent
			// AuthenticationManager already published it
			if (parentResult == null) {
				this.eventPublisher.publishAuthenticationSuccess(result);
			}

			return result;
		}

		// Parent was null, or didn't authenticate (or throw an exception).
		if (lastException == null) { 1. 若匹配不到相应的 `AuthenticationProvider` 抛出 ProviderNotFoundException 异常 // [!code ++]
			lastException = new ProviderNotFoundException(this.messages.getMessage("ProviderManager.providerNotFound",
					new Object[] { toTest.getName() }, "No AuthenticationProvider found for {0}"));
		}
		// If the parent AuthenticationManager was attempted and failed then it will
		// publish an AbstractAuthenticationFailureEvent
		// This check prevents a duplicate AbstractAuthenticationFailureEvent if the
		// parent AuthenticationManager already published it
		if (parentException == null) {
			prepareException(lastException, authentication);
		}
		throw lastException;
	}
```


3. `AuthenticationProvider` 是认证类的提供者其实现类 `DaoAuthenticationProvider` 专注于处理 `UsernamePasswordAuthenticationToken` 的认证请求

![image-20240825102932802](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408251029951.png)

4. `DaoAuthenticationProvider` 认证类调用 `retrieveUser` 方法实现对用户名的检索、检索成功后返回 `UserDetails`

```java
@Override
 	//1. 对用户名的检索 // [!code ++]
	protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) 
			throws AuthenticationException {
		prepareTimingAttackProtection();
		try {
            // 2. 检索成功后返回 `UserDetails`  // [!code ++] 
			UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
			if (loadedUser == null) {
				throw new InternalAuthenticationServiceException(
						"UserDetailsService returned null, which is an interface contract violation");
			}
			return loadedUser;
		}
		catch (UsernameNotFoundException ex) {
			mitigateAgainstTimingAttack(authentication);
			throw ex;
		}
		catch (InternalAuthenticationServiceException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
		}
	}
```

5. `DaoAuthenticationProvider` 认证类调用 `additionalAuthenticationChecks` 方法实现对密码的检索成功后将 `Authentication` 信息存储到 `SecurityContextHolder` 对象中以供后续 Filter 使用

```java
	@Override
	@SuppressWarnings("deprecation")
 	//1. 专注于处理 `UsernamePasswordAuthenticationToken` 的认证请求 // [!code ++]
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		if (authentication.getCredentials() == null) {
			this.logger.debug("Failed to authenticate since no credentials provided");
			throw new BadCredentialsException(this.messages
				.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
		String presentedPassword = authentication.getCredentials().toString();
		if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            //2. 对密码的检索 // [!code ++]
			this.logger.debug("Failed to authenticate since password does not match stored value");
			throw new BadCredentialsException(this.messages
				.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
	}
```

通过上述对 Spring Security  表单登录认证流程的梳理我们可以得出我们可以将第四步中对用户名进行检索替换为对数据库中用户的检索就可以实现自定义 ORM 框架基于 DB 数据库进行认证，那么我们如何进行操作呢？我们可以查看下第四步中 `retrieveUser` 方法是如何进行用户名的检索操作的：

```java
		try {
            // 获取 UserDetailsService 后调用 loadUserByUsername 方法进行用户名检索 // [!code ++] 
			UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
			if (loadedUser == null) {
				throw new InternalAuthenticationServiceException(
						"UserDetailsService returned null, which is an interface contract violation");
			}
			return loadedUser;
		}
```

因此我们可以将其替换为手动实现：

```java
@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService, UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }
}
```

实现基于数据库的  `loadUserByUsername` 方法

```java
@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService, UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getUsername, username));
        if (Objects.isNull(account)) {
            throw new UsernameNotFoundException(username);
        }
        return User.builder()
                .username(account.getUsername())
                // 因为我们没有配置指定的密码加密器为了防止匹配不到相应的加密器此处手动指定为 noop // [!code ++] 
                .password("{noop}" +  account.getPassword())
                .roles(account.getRole())
                .build();
    }
}
```

访问 `localhost:8083/login`进行验证

![image-20240825105633743](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408251056909.png)

![image-20240825105645527](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408251056685.png)

![image-20240825105656631](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408251056303.png)

# 四、用户注册、密码升级

> [!NOTE] 
>
> 此处我们提及到的用户注册是指在 Spring Security  中通过 `UserDetailsManager` 提供的方法实现认证用户保存到 DB 中的操作

## 4.1 用户注册

1. 实现 `UserDetailsManager` 中 `register` 方法

```java
@Data
public class RegisterVo {
    private String username;
    private String password;
    private String email;
}
```

```java
public interface AccountService extends IService<Account>, UserDetailsService {
    boolean register(RegisterVo vo);
    boolean userExistsByUsername(String username);
    boolean userExistsByEmail(String email);
}
```

```java
@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {

    @Override
    public UserDetails loadUserByUsername(String text) throws UsernameNotFoundException {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getUsername, text).or().eq(Account::getEmail, text));
        if (Objects.isNull(account)) {
            throw new UsernameNotFoundException(text);
        }
        return User.builder()
                .username(account.getUsername())
                // 因为我们没有配置指定的密码加密器为了防止匹配不到相应的加密器此处手动指定为 noop
                .password("{noop}" + account.getPassword())
                .roles(account.getRole())
                .build();
    }

    @Override
    public boolean register(RegisterVo vo) {
        if (this.userExistsByUsername(vo.getUsername()) || this.userExistsByEmail(vo.getEmail())) {
            throw new UserNameAlreadyExistException("用户名或邮箱已被注册");
        } else {
            Account account = new Account();
            account.setUsername(vo.getUsername());
            account.setPassword(vo.getPassword());
            account.setEmail(vo.getEmail());
            return this.save(account);
        }
    }

    @Override
    public boolean userExistsByUsername(String username) {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getUsername, username));
        return account != null;
    }

    @Override
    public boolean userExistsByEmail(String email) {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getEmail, email));
        return account != null;
    }
}
```

```java
public class UserNameAlreadyExistException extends RuntimeException {
    public UserNameAlreadyExistException(String message) {
        super(message);
    }
}
```

```java
@RestControllerAdvice
public class AuthException {
    @ExceptionHandler(UsernameNotFoundException.class)
    private RestBean<String> userNameAlreadyExistException(){
        return RestBean.failure(HttpStatus.BAD_REQUEST.value(), "用户名或邮箱已被注册");
    }

}
```



2. 创建相关 API

```java
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
```

3. 放行相关接口

```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.
                        requestMatchers("/api/users/**").permitAll()
                        .requestMatchers("/api/auths/**").permitAll() // [!code ++]
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
```

4. 测试

```java
    @Test
    void testRegisterWithAlreadyExistUsername() {
        RegisterVo vo = new RegisterVo();
        vo.setUsername("mcdd1024");
        vo.setPassword("123abc");
        vo.setEmail("not-exist@qq.com");
        assertThrows(UserNameAlreadyExistException.class, () -> service.register(vo));
    }
    @Test
    void testRegisterWithAlreadyExistEmail() {
        RegisterVo vo = new RegisterVo();
        vo.setUsername("not-exist");
        vo.setPassword("123abc");
        vo.setEmail("mcdd1024@qq.com");
        assertThrows(UserNameAlreadyExistException.class, () -> service.register(vo));
    }
    @Test
    void testRegisterWithDifferentUsername() {
        RegisterVo vo = new RegisterVo();
        vo.setUsername("mcdd01");
        vo.setPassword("123abc");
        vo.setEmail("mcdd01@qq.com");
        assertTrue(service.register(vo));
    }
```

![image-20240825201549277](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408252015438.png)

## 4.2 密码升级

上面我们完成了新用户注册的逻辑，那对于已注册的旧用户（密码为明文存储）如果我们希望升级其密码安全该如何操作呢？

![image-20240825202044798](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408252020979.png)

在 Spring Security 中管理密码升级的接口为 `UserDetailsPasswordService` 该接口在用户完成登录认证后会自动开启对密码的升级操作

```java
public interface UserDetailsPasswordService {

	/**
	 * Modify the specified user's password. This should change the user's password in the
	 * persistent user repository (database, LDAP etc).
	 * @param user the user to modify the password for
	 * @param newPassword the password to change to, encoded by the configured
	 * {@code PasswordEncoder}
	 * @return the updated UserDetails with the new password
	 */
	UserDetails updatePassword(UserDetails user, String newPassword);

}
```

下面为具体操作

1. 添加修改密码的方法

```java
public interface AccountService extends IService<Account>, UserDetailsService, UserDetailsPasswordService {
    boolean register(RegisterVo vo);

    boolean userExistsByUsername(String username);

    boolean userExistsByEmail(String email);

    boolean updatePasswordByUsernameOrEmail(String text , String newPassword);
}
```

```java
    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        boolean updated = this.updatePasswordByUsernameOrEmail(user.getUsername(), newPassword);
        return updated ? user : null;
    }

    @Override
    public boolean updatePasswordByUsernameOrEmail(String text, String newPassword) {
        if (!this.userExistsByUsername(text) && !this.userExistsByEmail(text)) {
            throw new UsernameNotFoundException("没有指定用户名或邮箱的用户");
        } else {
            return this.update(new LambdaUpdateWrapper<Account>()
                    .set(Account::getPassword, newPassword)
                    .in(Account::getUsername, text)
                    .or()
                    .in(Account::getEmail, text));
        }
    }
```

2. 测试

```java
    @Test
    void testUpdatePasswordByUsernameOrEmail() {
        boolean updated01 = service.updatePasswordByUsernameOrEmail("mcdd01", "updated-password");
        assertTrue(updated01);
        boolean updated02 = service.updatePasswordByUsernameOrEmail("mcdd1024@qq.com", "updated-password");
        assertTrue(updated02);
        assertThrows(UsernameNotFoundException.class, () -> service.updatePasswordByUsernameOrEmail("not-exist@qq.com", "updated-password"));
        assertThrows(UsernameNotFoundException.class, () -> service.updatePasswordByUsernameOrEmail("not-exist", "updated-password"));
    }
```

![image-20240825205918100](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408252059326.png)

进行升级操作

![image-20240825210045308](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408252100527.png)

假定我们要升级的用户为 test ,访问 `localhost:8083/login`

![image-20240825211832412](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408252118640.png)

注意升级完成后我们可以将默认的密码加密器设置为 `BCryptPasswordEncoder`

```java
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

修改 loadUserByUsername 方法中获取 UserDetails 逻辑 

```java
    @Override
    public UserDetails loadUserByUsername(String text) throws UsernameNotFoundException {
        Account account = this.getOne(new LambdaQueryWrapper<Account>().eq(Account::getUsername, text).or().eq(Account::getEmail, text));
        if (Objects.isNull(account)) {
            throw new UsernameNotFoundException(text);
        }
        return User.builder()
                .username(account.getUsername())
                .password(account.getPassword()) // [!code ++]
                .roles(account.getRole())
                .build();
    }
```

现在默认的加密器被我们替换为 BCryptPasswordEncoder 所以密码前缀可以不需要了,下面我们对数据库进行清理

![image-20240825212131201](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408252121418.png)

重新启动并验证 cxk + cxk123

![image-20240825212304782](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408252123984.png)

# 五、JSON 格式返回结果



