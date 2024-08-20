import{_ as s,c as i,o as a,a7 as n}from"./chunks/framework.BCmJPHGq.js";const E=JSON.parse('{"title":"第一个 SpringSecurity 程序","description":"","frontmatter":{},"headers":[],"relativePath":"demo/demo01.md","filePath":"demo/demo01.md","lastUpdated":1724167242000}'),t={name:"demo/demo01.md"},e=n(`<h1 id="第一个-springsecurity-程序" tabindex="-1">第一个 SpringSecurity 程序 <a class="header-anchor" href="#第一个-springsecurity-程序" aria-label="Permalink to &quot;第一个 SpringSecurity 程序&quot;">​</a></h1><div class="note custom-block github-alert"><p class="custom-block-title">内容</p><p></p><ul><li>Spring Security 概述</li><li>认证、授权相关概念</li><li>快速入门</li></ul></div><h1 id="一、什么是-spring-security" tabindex="-1">一、什么是 Spring Security <a class="header-anchor" href="#一、什么是-spring-security" aria-label="Permalink to &quot;一、什么是 Spring Security&quot;">​</a></h1><p>Spring Security 是一个 Java 框架，用于保护应用程序的安全性。它提供了一套全面的安全解决方案，包括身份验证、授权、防止攻击等功能。Spring Security 基于过滤器链的概念，可以轻松地集成到任何基于 Spring 的应用程序中。它支持多种身份验证选项和授权策略，开发人员可以根据需要选择适合的方式。此外，Spring Security 还提供了一些附加功能，如集成第三方身份验证提供商和单点登录，以及会话管理和密码编码等。总之，Spring Security 是一个强大且易于使用的框架，可以帮助开发人员提高应用程序的安全性和可靠性。</p><p>Spring Security是一个框架，提供 <a href="https://springdoc.cn/spring-security/features/authentication/index.html" target="_blank" rel="noreferrer">认证（authentication）</a>、<a href="https://springdoc.cn/spring-security/features/authorization/index.html" target="_blank" rel="noreferrer">授权（authorization）</a> 和 <a href="https://springdoc.cn/spring-security/features/exploits/index.html" target="_blank" rel="noreferrer">保护，以抵御常见的攻击</a>。它对保护命令式和响应式应用程序有一流的支持，是保护基于Spring的应用程序的事实标准。</p><hr><p>官网介绍</p><blockquote><ul><li><p>英文：Spring Security is a powerful and highly customizable authentication and access-control framework. It is the de-facto standard for securing Spring-based applications.</p></li><li><p>中文：Spring Security 是一个功能强大、高度可定制的身份验证和访问控制框架。它是确保基于 Spring 的应用程序安全的事实标准。</p></li></ul></blockquote><hr><blockquote><ul><li>英文：Spring Security is a framework that focuses on providing both authentication and authorization to Java applications. Like all Spring projects, the real power of Spring Security is found in how easily it can be extended to meet custom requirements</li><li>中文：Spring Security 是一个专注于为 Java 应用程序提供身份验证和授权的框架。与所有 Spring 项目一样，Spring Security 的真正威力在于它可以轻松扩展以满足自定义需求</li></ul></blockquote><ul><li><a href="https://spring.io/projects/spring-security" target="_blank" rel="noreferrer">官方文档（英文）</a></li></ul><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201611216.png" alt="image-20240820161151113"></p><ul><li><a href="https://springdoc.cn/spring-security/" target="_blank" rel="noreferrer">社区文档 （社区）</a></li></ul><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201612987.png" alt="image-20240820161201891"></p><p>Spring Security 支持以下几点特性：</p><table tabindex="0"><thead><tr><th>英文</th><th>中文</th></tr></thead><tbody><tr><td>Comprehensive and extensible support for both Authentication and Authorization</td><td>为身份验证和授权提供全面、可扩展的支持</td></tr><tr><td>Protection against attacks like session fixation, clickjacking, cross site request forgery, etc</td><td>防止会话固定、点击劫持、跨站请求伪造等攻击</td></tr><tr><td>Servlet API integration</td><td>集成 Servlet API</td></tr><tr><td>Optional integration with Spring Web MVC</td><td>可选择与 Spring Web MVC 集成</td></tr></tbody></table><h1 id="二、什么是认证" tabindex="-1">二、什么是认证 <a class="header-anchor" href="#二、什么是认证" aria-label="Permalink to &quot;二、什么是认证&quot;">​</a></h1><p>Spring Security 提供了对 <a href="https://en.wikipedia.org/wiki/Authentication" target="_blank" rel="noreferrer">认证（Authentication）</a> 的全面支持。<strong>认证是指我们如何验证试图访问特定资源的人的身份</strong>。一个常见的验证用户的方法是要求用户输入用户名和密码。一旦进行了认证，我们就知道了身份并可以执行授权。</p><p>与认证方面相关的 HTTP 响应码：<code>401 Unatuthorized</code></p><h1 id="三、什么是授权" tabindex="-1">三、什么是授权 <a class="header-anchor" href="#三、什么是授权" aria-label="Permalink to &quot;三、什么是授权&quot;">​</a></h1><p>Spring Security 为 <a href="https://en.wikipedia.org/wiki/Authorization" target="_blank" rel="noreferrer">授权 （Authorization ）</a> 提供全面支持。<strong>授权是指确定允许谁访问特定资源</strong>。Spring Security 允许基于请求的授权和基于方法的授权，从而提供 <a href="https://en.wikipedia.org/wiki/Defense_in_depth_(computing)" target="_blank" rel="noreferrer">深度防御</a>。</p><p>与授权方面相关的 HTTP 响应码：<code>403 Forbidden</code></p><h1 id="四、快速入门" tabindex="-1">四、快速入门 <a class="header-anchor" href="#四、快速入门" aria-label="Permalink to &quot;四、快速入门&quot;">​</a></h1><div class="tip custom-block github-alert"><p class="custom-block-title">先决条件</p><p></p><p>Spring Security 要求有 Java 8 或更高的运行环境。由于 Spring Security 旨在以独立的方式运行，你不需要在你的 Java 运行时环境中放置任何特殊的配置文件。特别是，你不需要配置一个特殊的 Java 认证和授权服务（JAAS）策略文件，也不需要把 Spring Security 放到普通的 classpath 位置。</p><p>同样地，如果你使用 EJB 容器或 Servlet 容器，你不需要把任何特殊的配置文件放在任何地方，也不需要把 Spring Security 包含在服务器的 classloader 中。所有需要的文件都包含在你的应用程序中。</p><p>这种设计提供了最大的部署时间灵活性，因为你可以将你的目标工件（无论是 JAR、WAR 还是 EAR）从一个系统复制到另一个系统，并立即运行。</p></div><p>本处采用：</p><table tabindex="0"><thead><tr><th style="text-align:center;">TOOLS</th><th style="text-align:center;">VERSION</th></tr></thead><tbody><tr><td style="text-align:center;">IntelliJ IDEA (Ultimate Edition) | Maven | OpenJDK</td><td style="text-align:center;">2024.2.0.1 | 3.9.8 | 17.0.11 2024-04-16 LTS</td></tr><tr><td style="text-align:center;">Spring Boot | Spring Security</td><td style="text-align:center;">3.1.7 | 6.1.6</td></tr></tbody></table><ol><li>创建工程</li></ol><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201626525.png" alt="image-20240820162633647"></p><ol start="2"><li>引入依赖</li></ol><div class="language-xml vp-adaptive-theme line-numbers-mode"><button title="Copy Code" class="copy"></button><span class="lang">xml</span><pre class="shiki shiki-themes github-light github-dark vp-code" tabindex="0"><code><span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&lt;</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">dependency</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    &lt;</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">groupId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;org.springframework.boot&lt;/</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">groupId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    &lt;</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">artifactId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;spring-boot-starter-web&lt;/</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">artifactId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&lt;/</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">dependency</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&lt;</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">dependency</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    &lt;</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">groupId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;org.springframework.boot&lt;/</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">groupId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    &lt;</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">artifactId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;spring-boot-starter-security&lt;/</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">artifactId</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&lt;/</span><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">dependency</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">&gt;</span></span></code></pre><div class="line-numbers-wrapper" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br></div></div><ol start="3"><li>创建相关包并添加测试资源</li></ol><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201628876.png" alt="image-20240820162808772"></p><p>添加测试资源</p><div class="language-java vp-adaptive-theme line-numbers-mode"><button title="Copy Code" class="copy"></button><span class="lang">java</span><pre class="shiki shiki-themes github-light github-dark vp-code" tabindex="0"><code><span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">Controller</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">RequestMapping</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&quot;/api/users&quot;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">)</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">public</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> class</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> UserController</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    @</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">ResponseBody</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    @</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">GetMapping</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">&quot;sayHello&quot;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">)</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">    public</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> String </span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">sayHello</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">() {</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">        return</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> &quot;hello&quot;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">;</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">    }</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre><div class="line-numbers-wrapper" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br></div></div><ol start="4"><li>启动并测试</li></ol><p>访问 <code>http://localhost:8080/api/users/sayHello</code> 出现下面界面</p><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201635108.png" alt="image-20240820163557012"></p><p>这时候我们的应用程序就被 Spring Security 保护了</p><div class="tip custom-block github-alert"><p class="custom-block-title">这个时候我们可以思考以下问题：</p><p></p><ol><li>账号、密码是什么呢可以自定义吗</li><li>这个登录页面是从哪里来的呢</li></ol><p>下面我们将依次探究上述问题</p></div><p>关于上述 账号密码是什么的问题 我们打开 IDEA 控制台发现 Spring Boot 启动日志中打印出</p><div class="language-sh vp-adaptive-theme line-numbers-mode"><button title="Copy Code" class="copy"></button><span class="lang">sh</span><pre class="shiki shiki-themes github-light github-dark vp-code" tabindex="0"><code><span class="line"><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">Using</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> generated</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> security</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> password:</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> 4d60ab17-9534-49ef-9b8b-aab78068cd99</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">This</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> generated</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> password</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> is</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> for</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> development</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> use</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> only.</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> Your</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> security</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> configuration</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> must</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> be</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> updated</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> before</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> running</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> your</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> application</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> in</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> production.</span></span></code></pre><div class="line-numbers-wrapper" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br></div></div><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201633613.png" alt="image-20240820163314501"></p><p>根据提示我们可以得知默认生成的密码为 <code>4d60ab17-9534-49ef-9b8b-aab78068cd99</code> 但此处没有用户名相关信息（默认情况下用户名为 <code>user</code>）接下来我们使用上述信息进行登录</p><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201640531.png" alt="image-20240820164052434"></p><p>可以看到我们已经访问成功了，接下来我们探究 用户名和密码可以自定义吗这个问题，答案是可以的我们可以通过配置文件的方式为我们的程序配置指定的用户名和密码</p><div class="language-yaml vp-adaptive-theme line-numbers-mode"><button title="Copy Code" class="copy"></button><span class="lang">yaml</span><pre class="shiki shiki-themes github-light github-dark vp-code" tabindex="0"><code><span class="line"><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">spring</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">:</span></span>
<span class="line"><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">  security</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">:</span></span>
<span class="line"><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">    user</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">:</span></span>
<span class="line"><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">      name</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">root</span></span>
<span class="line"><span style="--shiki-light:#22863A;--shiki-dark:#85E89D;">      password</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">: </span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;">root</span></span></code></pre><div class="line-numbers-wrapper" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br></div></div><p>配置好后我们重启服务器（此时默认生成的密码已经不再打印了，因为我们已经配置了指定的用户信息）</p><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201650065.png" alt="image-20240820165030956"></p><p>继续访问 <code>http://localhost:8080/api/users/sayHello</code> 输入 root + root</p><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201651616.png" alt="image-20240820165135506"></p><p>可以看到成功访问，此时我们已经实现了如何自定义用户名和密码，接下来让我们来探究第二个问题，这个登陆页面是从哪里来的呢</p><p>既然我们是通过 starter 的方式引入的 Spring Security 那么我们可以通过 AutoConfiguration 来观察下引入 Spring Security 后我们引入了那些组件</p><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201655374.png" alt="image-20240820165512240"></p><p>该类代码如下：</p><div class="language-java vp-adaptive-theme line-numbers-mode"><button title="Copy Code" class="copy"></button><span class="lang">java</span><pre class="shiki shiki-themes github-light github-dark vp-code" tabindex="0"><code><span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">AutoConfiguration</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">before</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> UserDetailsServiceAutoConfiguration.class)</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">ConditionalOnClass</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(DefaultAuthenticationEventPublisher.class)</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">EnableConfigurationProperties</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(SecurityProperties.class)</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">Import</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">public</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> class</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> SecurityAutoConfiguration</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">	@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">Bean</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">	@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">ConditionalOnMissingBean</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(AuthenticationEventPublisher.class)</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">	public</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> DefaultAuthenticationEventPublisher </span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">authenticationEventPublisher</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(ApplicationEventPublisher </span><span style="--shiki-light:#E36209;--shiki-dark:#FFAB70;">publisher</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">) {</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">		return</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> new</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> DefaultAuthenticationEventPublisher</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(publisher);</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">	}</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre><div class="line-numbers-wrapper" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br></div></div><p>其中我们重点关注 <code>@Import({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })</code> 中的 <code>SpringBootWebSecurityConfiguration</code> 类，点击查看</p><div class="language-java vp-adaptive-theme line-numbers-mode"><button title="Copy Code" class="copy"></button><span class="lang">java</span><pre class="shiki shiki-themes github-light github-dark vp-code" tabindex="0"><code><span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">Configuration</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">proxyBeanMethods</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> false</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">)</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">ConditionalOnWebApplication</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">type</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> Type.SERVLET)</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">class</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> SpringBootWebSecurityConfiguration</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">	/**</span></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">	 * The default configuration for web security. It relies on Spring Security&#39;s</span></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">	 * content-negotiation strategy to determine what sort of authentication to use. If</span></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">	 * the user specifies their own {@link SecurityFilterChain} bean, this will back-off</span></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">	 * completely and the users should specify all the bits that they want to configure as</span></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">	 * part of the custom security configuration.</span></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">	 */</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">	@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">Configuration</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;">proxyBeanMethods</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> =</span><span style="--shiki-light:#005CC5;--shiki-dark:#79B8FF;"> false</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">)</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">	@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">ConditionalOnDefaultWebSecurity</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">	static</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;"> class</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;"> SecurityFilterChainConfiguration</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> {</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">		@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">Bean</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">		@</span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">Order</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(SecurityProperties.BASIC_AUTH_ORDER)</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">		SecurityFilterChain </span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">defaultSecurityFilterChain</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(HttpSecurity </span><span style="--shiki-light:#E36209;--shiki-dark:#FFAB70;">http</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">) </span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">throws</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> Exception {</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">			http.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">authorizeHttpRequests</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">((requests) </span><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">-&gt;</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> requests.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">anyRequest</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">().</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">authenticated</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">());</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">			http.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">formLogin</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">withDefaults</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">());</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">			http.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">httpBasic</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">(</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">withDefaults</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">());</span></span>
<span class="line"><span style="--shiki-light:#D73A49;--shiki-dark:#F97583;">			return</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;"> http.</span><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">build</span><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">();</span></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">		}</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">	}</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#6A737D;--shiki-dark:#6A737D;">    //...</span></span>
<span class="line"></span>
<span class="line"><span style="--shiki-light:#24292E;--shiki-dark:#E1E4E8;">}</span></span></code></pre><div class="line-numbers-wrapper" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br></div></div><p>注意到该类中有一个名为 <code>SecurityFilterChainConfiguration</code> 的静态方法，下面我们给出注释的翻译</p><div class="language-sh vp-adaptive-theme line-numbers-mode"><button title="Copy Code" class="copy"></button><span class="lang">sh</span><pre class="shiki shiki-themes github-light github-dark vp-code" tabindex="0"><code><span class="line"><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">Web</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> 安全性的默认配置。它依赖于</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> Spring</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> Security</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> 的内容协商策略来确定要使用的身份验证类型</span></span>
<span class="line"><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">如果用户指定了自己的</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> SecurityFilterChain</span><span style="--shiki-light:#032F62;--shiki-dark:#9ECBFF;"> bean，这将完全退出</span></span>
<span class="line"><span style="--shiki-light:#6F42C1;--shiki-dark:#B392F0;">用户应指定他们想要配置的所有位，作为自定义安全配置的一部分。</span></span></code></pre><div class="line-numbers-wrapper" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br></div></div><p>结合注释不难得出，该类主要用于进行默认安全配置，且方法名中的 Filter 表明该类大概率和过滤器有关，下面我们重点关注该类的方法参数和方法体：</p><ul><li><p>方法参数：<code>HttpSecurity http</code> 它允许为特定的 http 请求配置基于 Web 的安全性</p></li><li><p>方法体：</p><ul><li><p><code>http.authorizeHttpRequests((requests) -&gt; requests.anyRequest().authenticated()); </code>不难看出该代码主要用于配置需要拦截的资源 <code>requests </code> 其中 <code>requests.anyRequest().authenticated()</code> 表示所有资源都需要进行认证</p></li><li><p><code>http.formLogin(withDefaults());</code> 采用默认方式配置 <code>formLogin</code></p></li><li><p><code>http.httpBasic(withDefaults());</code> 采用默认方式配置 <code>httpBasic</code></p></li></ul></li><li><p>返回值：通过 <code>http.build()</code> 构造一个 <code>SecurityFilterChain </code> 后返回</p></li></ul><h1 id="五、其它-java-安全框架" tabindex="-1">五、其它 Java 安全框架 <a class="header-anchor" href="#五、其它-java-安全框架" aria-label="Permalink to &quot;五、其它 Java 安全框架&quot;">​</a></h1><ol><li><p><strong><a href="https://shiro.apache.org/" target="_blank" rel="noreferrer">Apache Shiro</a></strong>：</p><ul><li><strong>简介</strong>：Apache Shiro 是一个强大且灵活的开源安全框架，用于身份验证、授权、会话管理、加密和缓存。</li><li><strong>特点：</strong><ul><li>简单易用，易于集成。</li><li>支持多种身份验证方式，如用户名/密码、LDAP、OAuth、OpenID等。</li><li>支持细粒度的权限控制。</li><li>支持分布式会话管理。</li></ul></li><li><strong>应用场景</strong>：适用于需要简单安全解决方案的项目。</li></ul></li><li><p><strong><a href="https://sa-token.cc/index.html" target="_blank" rel="noreferrer">Sa-Token</a></strong></p><ul><li><strong>简介：</strong> <strong>Sa-Token</strong> 是一个轻量级 Java 权限认证框架，主要解决：<strong>登录认证</strong>、<strong>权限认证</strong>、<strong>单点登录</strong>、<strong>OAuth2.0</strong>、<strong>分布式Session会话</strong>、<strong>微服务网关鉴权</strong> 等一系列权限相关问题。</li><li><strong>特点：</strong><ul><li><strong>登录认证</strong> —— 单端登录、多端登录、同端互斥登录、七天内免登录。</li><li><strong>权限认证</strong> —— 权限认证、角色认证、会话二级认证。</li><li><strong>踢人下线</strong> —— 根据账号id踢人下线、根据Token值踢人下线。</li><li><strong>注解式鉴权</strong> —— 优雅的将鉴权与业务代码分离。</li><li><strong>路由拦截式鉴权</strong> —— 根据路由拦截鉴权，可适配 restful 模式。</li><li><strong>Session会话</strong> —— 全端共享Session,单端独享Session,自定义Session,方便的存取值。</li><li><strong>持久层扩展</strong> —— 可集成 Redis，重启数据不丢失。</li><li><strong>前后台分离</strong> —— APP、小程序等不支持 Cookie 的终端也可以轻松鉴权。</li><li><strong>Token风格定制</strong> —— 内置六种 Token 风格，还可：自定义 Token 生成策略。</li><li><strong>记住我模式</strong> —— 适配 [记住我] 模式，重启浏览器免验证。</li><li><strong>二级认证</strong> —— 在已登录的基础上再次认证，保证安全性。</li><li><strong>模拟他人账号</strong> —— 实时操作任意用户状态数据。</li><li><strong>临时身份切换</strong> —— 将会话身份临时切换为其它账号。</li><li><strong>同端互斥登录</strong> —— 像QQ一样手机电脑同时在线，但是两个手机上互斥登录。</li><li><strong>账号封禁</strong> —— 登录封禁、按照业务分类封禁、按照处罚阶梯封禁。</li><li><strong>密码加密</strong> —— 提供基础加密算法，可快速 MD5、SHA1、SHA256、AES 加密。</li><li><strong>会话查询</strong> —— 提供方便灵活的会话查询接口。</li><li><strong>Http Basic认证</strong> —— 一行代码接入 Http Basic、Digest 认证。</li><li><strong>全局侦听器</strong> —— 在用户登陆、注销、被踢下线等关键性操作时进行一些AOP操作。</li><li><strong>全局过滤器</strong> —— 方便的处理跨域，全局设置安全响应头等操作。</li><li><strong>多账号体系认证</strong> —— 一个系统多套账号分开鉴权（比如商城的 User 表和 Admin 表）</li><li><strong>单点登录</strong> —— 内置三种单点登录模式：同域、跨域、同Redis、跨Redis、前后端分离等架构都可以搞定。</li><li><strong>单点注销</strong> —— 任意子系统内发起注销，即可全端下线。</li><li><strong>OAuth2.0认证</strong> —— 轻松搭建 OAuth2.0 服务，支持openid模式 。</li><li><strong>分布式会话</strong> —— 提供共享数据中心分布式会话方案。</li><li><strong>微服务网关鉴权</strong> —— 适配Gateway、ShenYu、Zuul等常见网关的路由拦截认证。</li><li><strong>RPC调用鉴权</strong> —— 网关转发鉴权，RPC调用鉴权，让服务调用不再裸奔</li><li><strong>临时Token认证</strong> —— 解决短时间的 Token 授权问题。</li><li><strong>独立Redis</strong> —— 将权限缓存与业务缓存分离。</li><li><strong>Quick快速登录认证</strong> —— 为项目零代码注入一个登录页面。</li><li><strong>标签方言</strong> —— 提供 Thymeleaf 标签方言集成包，提供 beetl 集成示例。</li><li><strong>jwt集成</strong> —— 提供三种模式的 jwt 集成方案，提供 token 扩展参数能力。</li><li><strong>RPC调用状态传递</strong> —— 提供 dubbo、grpc 等集成包，在RPC调用时登录状态不丢失。</li><li><strong>参数签名</strong> —— 提供跨系统API调用签名校验模块，防参数篡改，防请求重放。</li><li><strong>自动续签</strong> —— 提供两种Token过期策略，灵活搭配使用，还可自动续签。</li><li><strong>开箱即用</strong> —— 提供SpringMVC、WebFlux、Solon 等常见框架集成包，开箱即用。</li><li><strong>最新技术栈</strong> —— 适配最新技术栈：支持 SpringBoot 3.x，jdk 17。</li></ul></li></ul></li></ol><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201709250.png" alt="image-20240820170907068"></p><p><img src="https://mcdd-dev-1311841992.cos.ap-beijing.myqcloud.com/assets/202408201708719.png" alt="image-20240820170851602"></p>`,65),l=[e];function p(r,h,k,o,d,g){return a(),i("div",null,l)}const u=s(t,[["render",p]]);export{E as __pageData,u as default};
