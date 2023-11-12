package demo.config;

import demo.userdetail.DemoUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.annotation.Resource;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig {

    @Resource
    private DemoUserDetailService userDetailService;
    @Resource
    private PasswordEncoder passwordEncoder;
    @Resource
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeRequests(authorRequest ->
                        authorRequest.anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder builder) throws Exception {
        builder
                .userDetailsService(userDetailService)
                 .passwordEncoder(passwordEncoder);
    }

    /**
     * @deprecated AuthenticationManager实例在HttpSecurity的beforeConfigure中初始化
     */
    @Deprecated
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
