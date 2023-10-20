package learn.util;

import com.aliyun.dysmsapi20170525.Client;
import com.aliyun.dysmsapi20170525.models.SendSmsRequest;
import com.aliyun.dysmsapi20170525.models.SendSmsResponse;
import com.aliyun.teautil.models.RuntimeOptions;
import learn.config.AppProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SmsUtil {

    private final Client smsClient;

    private final AppProperties appProperties;

    public void sendSms(String code) throws Exception {
        SendSmsRequest sendSmsRequest = new SendSmsRequest();
        sendSmsRequest.setPhoneNumbers(appProperties.getSms().getTestPhone());
        sendSmsRequest.setSignName(appProperties.getSms().getSignName());
        sendSmsRequest.setTemplateCode("SMS_463598387");
        sendSmsRequest.setTemplateParam("{\"code\":\"" + code +"\"}");

        SendSmsResponse sendSmsResponse = smsClient.sendSms(sendSmsRequest);

        log.debug("发送状态：{}", sendSmsResponse.getStatusCode());
    }
}
