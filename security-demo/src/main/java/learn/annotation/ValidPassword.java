package learn.annotation;

import learn.validation.EmailValidator;
import learn.validation.PasswordConstraintValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.FIELD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordConstraintValidator.class)
@Documented
public @interface ValidPassword {
    String message() default "验证密码";

    //Validate验证必须的两个变量
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default { };
}
