package learn.service;

import learn.util.SmsUtil;
import learn.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SmsService {

    private final SmsUtil smsUtil;
    private final TotpUtil totpUtil;

    public void sendSms(String strKey) throws Exception {
        totpUtil.createTotp(strKey)
                .map(s -> {
                    try {
                        log.debug("生成验证码：{}", s);
                        smsUtil.sendSms(s);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return null;
                });
    }
}
