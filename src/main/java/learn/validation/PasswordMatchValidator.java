package learn.validation;

import learn.annotation.ValidMatchPassword;
import learn.entity.dto.UserDto;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
public class PasswordMatchValidator implements ConstraintValidator<ValidMatchPassword, UserDto> {
    @Override
    public void initialize(ValidMatchPassword constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    @Override
    public boolean isValid(UserDto value, ConstraintValidatorContext context) {
        return value.getPassword().equals(value.getMatchPassword());
    }
}
