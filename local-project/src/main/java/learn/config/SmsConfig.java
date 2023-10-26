package learn.config;

import com.aliyun.dysmsapi20170525.Client;
import com.aliyun.teaopenapi.models.Config;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Configuration
@RequiredArgsConstructor
public class SmsConfig {

    private final AppProperties appProperties;

    @Bean
    public Client createClient() throws Exception {
        Config config = new Config();
        config.setAccessKeyId(appProperties.getSms().getAccessId());
        config.setAccessKeySecret(appProperties.getSms().getAccessSecret());
        config.setEndpoint(appProperties.getSms().getEndPoint());
        return new Client(config);
    }
}
