package learn.service;

import learn.config.response.ResponseResult;
import learn.entity.Auth;
import learn.entity.User;
import learn.entity.dto.LoginDto;
import learn.mapper.UserMapper;
import learn.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.util.Optional;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final CacheUserService cacheUserService;

    public ResponseEntity<?> createAuthToken(LoginDto loginDto){
        return userMapper.queryUserByUserName(loginDto.getUsername())
                        .filter(u -> passwordEncoder.matches(loginDto.getPassword(), u.getPassword()))
                        .map(user -> {

                            //不进行二次认证
                            if (!user.getUsingMfa()){
                                return ResponseEntity.ok()
                                        .body(new Auth(jwtUtil.accessToken(user), jwtUtil.refreshToken(user)));
                            }
                            //进行二次认证
                            String mfaId = cacheUserService.catchUser(user);
;                            return ResponseEntity
                                    .status(HttpStatus.UNAUTHORIZED)
                                    .header("X-Authenticate","mfa", "mfaId=" + mfaId)
                                    .build();
                        })
                .orElseThrow(() -> new BadCredentialsException("账号或密码错误"));
    }

    public Optional<User> verifyTotp(String mfaId, String code) throws InvalidKeyException {
        return cacheUserService.verifyTotp(mfaId, code);
    }
}
