package demo.entity.dto;

import lombok.Data;
import lombok.NonNull;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.io.Serializable;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Data
public class UserDto implements Serializable {

    @NonNull
    @NotBlank
    @Size(min = 4, max = 10, message = "用户名长度必须在4-10之间")
    private String username;
    @NonNull
    private String password;
    @NonNull
    private String matchPassword;
    @NonNull
    private String email;
    @NonNull
    @NotBlank
    @Size(min = 2, max = 6, message = "姓名长度必须在2-6之间")
    private String name;
}
