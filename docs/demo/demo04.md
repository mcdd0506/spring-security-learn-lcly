# 进阶功能

> [!NOTE] 内容
>
> - 前后端分离下的自定义认证
> - 集成 JWT
> - 异常处理
> - 免鉴权（白名单）
> - 跨域处理
> - RememberMe
> - 会话管理

# 一、前后端分离下的自定义认证

通过前面的学习我们已经完成了 JSON 返回认证结果的功能以及 Spring Security 的认证流程我们知道 Spring Security 使用 `UsernamePasswordAuthenticationFilter` 进行认证处理，该过滤器通过获取 POST 请求中的表单数据 (username 和 password) 将其封装为 `UsernamePasswordAuthenticationToken` ,然后借助 `getAuthenticationManager` 获取  `AuthenticationManager` 调用该对象的 `authenticate` 传入上面封装好的 `UsernamePasswordAuthenticationToken` 对象完成认证

```java
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
        // 1. 获取 POST 请求中的表单数据 (username 和 password) 
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
		String username = obtainUsername(request);
		username = (username != null) ? username.trim() : "";
		String password = obtainPassword(request);
		password = (password != null) ? password : "";
        // 2. 将其封装为 `UsernamePasswordAuthenticationToken`
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
				password);
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
        // 3. 通过 `getAuthenticationManager` 获取 AuthenticationManager 对象然后调用的 `authenticate` 传入上面封装好的 `UsernamePasswordAuthenticationToken` 对象完成认证
		return this.getAuthenticationManager().authenticate(authRequest);
	}
    
}
```

基于前后段分离开发模式的需要前段喜爱嗯亩使用 Axios 发送请求，以 JSON 格式的数据作为请求参数发送给后端，后端通过相关 Controller 获取 JSON 数据然后通过自定义认证逻辑进行认证。

## 1.1 实现

### 自定义 AuthenticationManager

认证管理器 `AuthenticationManager` 的  `authenticate` 是发起认证的起源，因此我们首先需要将其手动实现以达到自定义认证的目的

```java
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService service) {
        // 匹配合适的 AuthenticationProvider 即 DaoAuthenticationProvider
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // 配置基于数据库认证的 UserDetailsService
        provider.setUserDetailsService(service);
        // 创建并返回认证管理器对象 (实现类 ProviderManager )
        return new ProviderManager(provider);
    }
```

### 创建认证 Service

```java
public interface AuthService {
    RestBean<String> login(LoginVo vo);
}
```

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;

    @Override
    public RestBean<String> login(LoginVo vo) {
        // 获取 username 和 password 并将其封装为
        String username = vo.getUsername();
        String password = vo.getPassword();
        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
                password);
        // 发起认证
        try {
            Authentication authentication = authenticationManager.authenticate(authRequest);
            if (authentication.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
                return RestBean.success("认证成功");
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
        }
        return RestBean.unauthorized("认证失败");
    }
}
```

---

```java
public interface AccountMapper extends BaseMapper<Account> {
}
```

```java
public interface AccountService extends IService<Account> , UserDetailsService {
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
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }
}
```

### 创建认证 Controller

```java
@Data
public class LoginVo {
    private String username;
    private String password;
}
```

```java
@RestController
@RequestMapping("/api/auths")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService service;

    @PostMapping("/login")
    public RestBean<String> login(@RequestBody LoginVo vo){
         return service.login(vo);
    }
}

```

### 关闭默认配置

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.
                        requestMatchers("/api/auths/**").permitAll()
                        .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable) // [!code ++]
                .formLogin(AbstractHttpConfigurer::disable); // [!code ++]
        return http.build();
    }
```

## 1.2 测试

### 通过 API 测试

```sh
curl -X "POST" "http://localhost:8084/api/auths/login" \
-H 'Content-Type: application/json' \
-d '{
  "username": "cxk",
  "password": "1234a56"
}' \

```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282253664.png)

```sh
curl -X "POST" "http://localhost:8084/api/auths/login" \
-H 'Content-Type: application/json' \
-d '{
  "username": "cxk",
  "password": "123456"
}' \

```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282253106.png)

### 通过前端页面测试

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <script src="https://unpkg.com/axios/dist/axios.min.js"></script>
</head>
<body>
<div id="app">
    登陆用户: <input type="text" id="username" autocomplete="off" v-model="username">
    <br/>
    密码: <input type="password" id="password" v-model="password">
    <br/>
    <input type="button" value="登陆" @click="login">
</div>

</body>
<script>
    axios.defaults.baseURL = 'http://localhost:8084/api/auths/';
    const appConfig = {
        data() {
            return {
                username: '',
                password: '',
            };
        },
        methods: {
            login() {
                let url = "/login";
                axios.post(url, {username: this.username, password: this.password})
                    .then(res => {
                        console.log(res.data);
                    })
                    .catch(err => {
                        console.log(err.data);
                    });
            }
        },
    }
    const app = Vue.createApp(appConfig);
    app.mount('#app');
</script>
<style>
    #app #username,
    #app #password {
        width: 150px;
    }
</style>
</html>
```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282314188.png)

可以看到此处出现了 cors 跨域问题,此处我们简单处理，后续将进行单独处理

```java
@RestController
@RequestMapping("/api/auths")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService service;

    @CrossOrigin // [!code ++]
    @PostMapping("/login")
    public RestBean<String> login(@RequestBody LoginVo vo){
         return service.login(vo);
    }
}
```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408282315021.png)

# 二、集成 JWT

JSON Web Token (JWT) 是一种用于在各方之间作为 JSON 对象安全传输信息的开放标准（RFC 7519）。它的主要特点是紧凑性和可自包含性。JWT 通常用于身份验证和信息交换。JWT 由三个部分组成，每部分之间用点 (`.`) 分隔：

1. **Header（头部）**
2. **Payload（负载）**
3. **Signature（签名）**

例如，一个 JWT 可能看起来像这样：
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Header（头部）

头部通常由两部分组成：令牌类型（即 JWT）和所使用的签名算法（如 HMAC SHA256 或 RSA）。
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
然后，这部分 JSON 对象会被 Base64Url 编码，形成 JWT 的第一部分。

Payload（负载）

负载部分包含声明（claims）。声明是关于实体（通常是用户）和其他数据的声明。声明可以分为三种类型：
- **Registered claims（注册声明）**：这些是预定义的声明，如 `iss`（发行者）、`exp`（过期时间）、`sub`（主题）、`aud`（受众）等。虽然它们是可选的，但建议使用。
- **Public claims（公共声明）**：可以自由定义，但为了避免冲突，应该在 IANA JSON Web Token Registry 或通过 URI 定义。
- **Private claims（私有声明）**：由双方之间约定使用，通常用于传递自定义信息。

例如：
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```
这个 JSON 对象也会被 Base64Url 编码，形成 JWT 的第二部分。

Signature（签名）

为了创建签名部分，您需要将编码后的头部和负载部分连接在一起，并使用指定的算法和一个密钥进行签名。
例如，如果使用 HMAC SHA256 算法，则签名部分的创建方式如下：
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```
签名用于验证消息在传输过程中是否未被篡改。签名部分会被附加到 JWT 的末尾，形成最终的 JWT 结构。

JWT 的使用

1. **身份认证**：用户在登录时提供凭证（如用户名和密码），服务器验证用户身份后，会生成一个 JWT 并返回给用户。用户在随后的请求中将 JWT 附加在 HTTP 请求头的 `Authorization` 字段中。服务器通过验证 JWT 来确认用户的身份。

2. **信息交换**：由于 JWT 可以携带声明，并且是经过签名的，所以可以确保信息的真实性和完整性。

安全注意事项

- **密钥保护**：在使用对称签名算法（如 HMAC SHA256）时，确保密钥的安全性非常重要。
- **过期时间**：设置合理的过期时间以减少令牌被滥用的风险。
- **HTTPS**：始终通过 HTTPS 传输 JWT 以防止中间人攻击。

## 2.1 JWT 快速上手

1. 引入依赖

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.0</version>
</dependency>
```

> [!CAUTION] 注意
>
> 如果 JDK 版本在 1.8 以上则需追加 jaxb-api 依赖
>
> ```xml
> <dependency>
>     <groupId>javax.xml.bind</groupId>
>     <artifactId>jaxb-api</artifactId>
>     <version>2.3.0</version>
> </dependency>
> ```

基本操作：

1. 生成 JWT

```java
    @Test
    void testGenerateToken() {
        String username = "admin";
        String token = Jwts.builder()
                // 头部
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                // 载荷
                .setId(UUID.randomUUID().toString())
                .setIssuer("demo06@issuer")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))
                .setSubject(username)
                // 签名
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
        System.out.println("token = " + token);
    }
```

![](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408291224145.png)

2. 解析 JWT

```java
    @Test
    void testVerifyToken() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4MTRjZWU1Ny1iZDgwLTQ0ZGMtYWRmYS03YTM4YWY2ODRlOWYiLCJpc3MiOiJkZW1vMDZAaXNzdWVyIiwiaWF0IjoxNzI0OTA1Mzk0LCJleHAiOjE3MjU1MTAxOTQsInN1YiI6ImFkbWluIn0.TwZKaDrrT-nhK5RVVSy8pB5Dw40em0Bet3XVk-Yqduk";
        Claims body = Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
        System.out.println("body = " + body);
    }
```

![image-20240829122433801](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408291224191.png)

JWT 工具类

```java
public class JWTUtils {
    private static final String SECRET = "123456";
    private static final Long EXPIRE = 1000 * 60 * 60 * 24 * 7L;

    /**
     * 生成 token
     *
     * @param subject subject
     * @return token
     */
    private static String generateToken(String subject) {
        return Jwts.builder()
                // 头部
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                // 载荷
                .setId(UUID.randomUUID().toString())
                .setIssuer("demo06@issuer")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))
                .setSubject(subject)
                // 签名
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    /**
     * 解析 token
     *
     * @param token token
     * @return Claims
     */
    private static Claims verifyToken(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
}
```

## 2.2 Redis 快速上手

1. 引入依赖

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-redis</artifactId>
  <version>3.1.7</version>
</dependency>
```

2. 配置

```yaml
spring:
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      database: 0
```

基本操作

1. 存入数据

```java
@SpringBootTest
public class RedisDemoTest {

    @Resource
    private RedisTemplate<String, String> redisTemplate;

    @Test
    void testSetValue() {
        redisTemplate.opsForValue().set("key", "value", 30, TimeUnit.SECONDS);
    }

}
```

2. 取出数据

```java
    @Test
    void testGetValue() {
        String value = redisTemplate.opsForValue().get("key");
        System.out.println("value = " + value);
    }
```

![image-20240829134706017](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408291353814.png)

注意到虽然确实可以存取但是存在乱码，因为 RedisTemplate 默认采用 JDK 内置的序列化类 (JdkSerializationRedisSerializer) 实现序列化操作，默认会将 key 和 value 序列化成 byte[] 导致许多客户端显示乱码，因此我们需要设置 Redis 配置，将默认的 JdkSerializationRedisSerializer 替换为 StringRedisSerializer

```java
@Configuration
public class RedisConfiguration {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        // key 采用 StringRedisSerializer 进行序列化
        template.setKeySerializer(new StringRedisSerializer());
        // key 采用 GenericJackson2JsonRedisSerializer 进行序列化
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
        return template;
    }
}
```

![image-20240829135334918](https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/202408291353986.png)

可以看到现在已经正常显示了

## 2.3 Spring Security 结合 JWT 实现登陆







# 三、异常处理

# 四、免鉴权（白名单）

# 五、跨域处理

# 六、RememberMe

# 七、会话管理

