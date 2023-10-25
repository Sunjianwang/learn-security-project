package learn.controller;

import learn.config.AppProperties;
import learn.entity.Auth;
import learn.entity.dto.LoginDto;
import learn.entity.dto.TotpVerificationDto;
import learn.exception.GlobalException;
import learn.service.AuthService;
import learn.service.SmsService;
import learn.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.nio.file.AccessDeniedException;
import java.security.InvalidKeyException;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AppProperties appProperties;
    private final SmsService smsService;
    private final JwtUtil jwtUtil;

    @PostMapping("token")
    public ResponseEntity<?> token(@Valid @RequestBody LoginDto loginDto){
        return authService.createAuthToken(loginDto);
    }

    @GetMapping("refreshToken")
    public Auth refreshToken(@RequestHeader(name = "Authorization") String authorization,
                             @RequestParam String refreshToken) throws AccessDeniedException {
        String token = authorization.replace(appProperties.getJwt().getPrefix(), "");
        if (jwtUtil.validAccessTokenWithOutExpireTime(token) && jwtUtil.validRefreshTokenWithExpireTime(refreshToken)){
            return new Auth(jwtUtil.createAccessTokenByRefreshToken(refreshToken), refreshToken);
        }
        throw new AccessDeniedException("拒绝访问");
    }

    @PostMapping("verifyTotp")
    public Auth verifyTotp(@Valid @RequestBody TotpVerificationDto verificationDto) throws InvalidKeyException, AccessDeniedException {
        return authService.verifyTotp(verificationDto.getMfaId(), verificationDto.getCode())
                .map(user ->
                    new Auth(jwtUtil.accessToken(user), jwtUtil.refreshToken(user))
                ).orElseThrow(() -> new GlobalException(HttpStatus.UNAUTHORIZED, "验证码不正确"));
    }

    @GetMapping("sendTotp")
    public void sendSmsCode(String strKey) throws Exception {
        smsService.sendSms(strKey);
    }
}
