package learn.controller;

import learn.service.SmsService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@RestController
@RequestMapping("sms")
@RequiredArgsConstructor
public class SmsController {

    private final SmsService smsService;

    @GetMapping("send")
    public void sendSmsCode(String strKey) throws Exception {
        smsService.sendSms(strKey);
    }
}
