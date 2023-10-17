package learn.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Configuration
@ConfigurationProperties(prefix = "learn")
public class AppProperties {

    @Getter
    @Setter
    private Jwt jwt = new Jwt();

    @Getter
    @Setter
    public static class Jwt{

        //访问令牌过期时间
        private Long accessTokenExpireTime = 60_000L;

        //刷新令牌过期时间
        private Long refreshTokenExpireTime = 60_000L;
    }
}
