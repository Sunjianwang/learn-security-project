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

        private String header = "Authorization";
        private String prefix = "Bearer ";
        private String secretKey = "learn";

        //访问令牌过期时间
        private Long accessTokenExpireTime = 60_000L;
        //刷新令牌过期时间
        private Long refreshTokenExpireTime = 60_000L;
    }

    @Setter
    @Getter
    private Sms sms = new Sms();

    @Getter
    @Setter
    public static class Sms{
        private String AccessId;
        private String AccessSecret;
        private String endPoint;
        private String testPhone;
        private String signName;
    }
}
