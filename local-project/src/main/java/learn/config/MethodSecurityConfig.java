package learn.config;

import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

/**
 * 开启方法级权限注解
 *
 * @author Sunjianwang
 * @version 1.0
 */
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {
}
