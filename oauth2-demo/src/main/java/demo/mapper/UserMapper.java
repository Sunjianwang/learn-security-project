package demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import demo.entity.User;
import org.apache.ibatis.annotations.Param;

import java.util.Optional;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
public interface UserMapper extends BaseMapper<User> {

    Optional<User> queryUserByUserName(@Param("username") String username);

    int updatePasswordByUserName(@Param("u") User user);
}
