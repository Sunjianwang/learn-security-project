package learn.userdetail;

import learn.entity.User;
import learn.mapper.UserMapper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Optional;

/**
 * 更新密码策略
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Service
public class LearnUserDetailsPassword implements UserDetailsPasswordService {

    @Resource
    private UserMapper userMapper;
    @Resource
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        User u = userMapper.queryUserByUserName(user.getUsername())
                .orElseThrow(() -> new BadCredentialsException("找不到用户"));
        u.setPassword(passwordEncoder.encode(newPassword));
        userMapper.updatePasswordByUserName(u);
        return u;
    }
}
