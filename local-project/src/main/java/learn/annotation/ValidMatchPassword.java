package learn.annotation;

import learn.validation.PasswordConstraintValidator;
import learn.validation.PasswordMatchValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.FIELD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordMatchValidator.class)
@Documented
public @interface ValidMatchPassword {
    String message() default "两次密码不一致";

    //Validate验证必须的两个变量
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default { };
}
