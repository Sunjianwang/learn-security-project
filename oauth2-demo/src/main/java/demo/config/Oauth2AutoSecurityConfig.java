package demo.config;

import demo.service.CustomOpaqueTokenIntrospector;
import demo.service.OAuth2RedisAuthorizationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Configuration
public class Oauth2AutoSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public OpaqueTokenIntrospector introspector(OAuth2RedisAuthorizationService authorizationService) {
        return new CustomOpaqueTokenIntrospector(authorizationService);
    }
}
