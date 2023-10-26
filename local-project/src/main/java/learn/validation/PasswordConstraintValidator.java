package learn.validation;

import learn.annotation.ValidPassword;
import lombok.RequiredArgsConstructor;
import org.passay.*;
import org.passay.spring.SpringMessageResolver;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;

/**
 * 密码验证
 *
 * @author Sunjianwang
 * @version 1.0
 */
@RequiredArgsConstructor
public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    private final SpringMessageResolver messageResolver;

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {

        PasswordValidator passwordValidator = new PasswordValidator(messageResolver, Arrays.asList(
                //长度规则
                new LengthRule(8),
                //至少包含一个大写英文字母
                new CharacterRule(EnglishCharacterData.UpperCase, 1),
                //至少包含一个小写英文字母
                new CharacterRule(EnglishCharacterData.LowerCase, 1),
                //至少包含一个特殊字符
                new CharacterRule(EnglishCharacterData.Special, 1),
                //不能有五个连续的字母
                new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 5, false),
                //不能有五个连续的数字
                new IllegalSequenceRule(EnglishSequenceData.Numerical, 5, false),
                //不能有五个连续的键盘字符
                new IllegalSequenceRule(EnglishSequenceData.USQwerty, 5, false),
                //不能有空格
                new WhitespaceRule()
        ));
        RuleResult result = passwordValidator.validate(new PasswordData(value));

        //禁用原有的消息处理
        context.disableDefaultConstraintViolation();
        //添加国际化定制的消息内容
        context.buildConstraintViolationWithTemplate(String.join(",", passwordValidator.getMessages(result))).addConstraintViolation();

        return result.isValid();
    }
}
