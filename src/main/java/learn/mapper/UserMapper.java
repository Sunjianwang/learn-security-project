package learn.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import learn.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
public interface UserMapper extends BaseMapper<User> {

    User queryUserByUserName(@Param("username") String username);

    int updatePasswordByUserName(@Param("u") User user);
}
