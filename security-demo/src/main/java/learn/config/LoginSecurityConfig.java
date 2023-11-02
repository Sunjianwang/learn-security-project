package learn.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * FormLogin安全配置
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Configuration
public class LoginSecurityConfig {

    @Bean
    @Order(100)
    public SecurityFilterChain loginSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .formLogin(login -> login
                        .loginPage("/login")
                        .failureUrl("/login?error")
                        .defaultSuccessUrl("/")
                        .permitAll())
                .logout(logout -> logout
                        .logoutUrl("/perform_logout")
                        .logoutSuccessUrl("/login")
                )
                .rememberMe(rememberMe -> rememberMe
                        .key("someSecret")
                        .tokenValiditySeconds(86400))
                .csrf(Customizer.withDefaults())
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .anyRequest().authenticated()).build();
    }

    /**
     * 在Spring Security5.7.0-M2之后，使用此方法进行Web安全配置
     * @return
     * @throws Exception
     */
    @Bean
    public WebSecurityCustomizer loginSecurityCustomizer() throws Exception {
        return
                //使某些资源不进行过滤器过滤
                web -> web.ignoring()
                        //放行静态资源
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
}
