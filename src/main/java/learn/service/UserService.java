package learn.service;

import learn.entity.User;
import learn.entity.dto.LoginDto;
import learn.mapper.UserMapper;
import learn.userdetail.LearnUserDetailsPassword;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final LearnUserDetailsPassword userDetailsPassword;

    /**
     * 获取Token时使用，判断是否需要进行密码编码升级
     * @param user          用户信息
     * @param rowPassword   密码明文
     */
    public void updatePasswordIfNeed(User user, String rowPassword){
        if (passwordEncoder.upgradeEncoding(user.getPassword())){
            userMapper.updatePasswordByUserName(user.withPassword(passwordEncoder.encode(rowPassword)));
        }
    }

    /**
     * 更新密码
     * @param userDto
     */
    public void updatePassword(LoginDto loginDto){
        userMapper.queryUserByUserName(loginDto.getUsername())
                        .map(user -> userDetailsPassword.updatePassword(user, passwordEncoder.encode(loginDto.getPassword()))
                        ).orElseThrow(() -> new BadCredentialsException("未找到用户"));
    }

    /**
     * 权限验证校验方法：校验用户名是否为当前登录用户
     * @param authentication
     * @param username
     * @return
     */
    public boolean checkCurrentUserName(Authentication authentication, String username){
        return authentication.getName().equals(username);
    }
}
