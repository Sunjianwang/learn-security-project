package learn.annotation;

import learn.validation.EmailValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.FIELD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EmailValidator.class)
@Documented
public @interface ValidEmail {
    String message() default "验证邮箱";

    //Validate验证必须的两个变量
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default { };
}
