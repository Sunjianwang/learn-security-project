package learn.service;

import learn.entity.Auth;
import learn.entity.dto.LoginDto;
import learn.mapper.UserMapper;
import learn.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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

    public Auth createAuthToken(LoginDto loginDto){
        return userMapper.queryUserByUserName(loginDto.getUsername())
                        .filter(u -> passwordEncoder.matches(loginDto.getPassword(), u.getPassword()))
                        .map(user -> new Auth(jwtUtil.accessToken(user), jwtUtil.refreshToken(user)))
                .orElseThrow(() -> new BadCredentialsException("账号或密码错误"));
    }
}
