package learn.controller;

import learn.config.AppProperties;
import learn.config.response.ResponseResult;
import learn.entity.Auth;
import learn.entity.dto.LoginDto;
import learn.service.AuthService;
import learn.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.nio.file.AccessDeniedException;

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
}
