package learn.exception;

import learn.config.response.ResponseResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;


@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * 参数校验失败抛出异常处理，统一错误返回格式
     * @author Sunjianwang
     * @param request 请求参数
     * @param e 异常
     * @return org.springframework.http.ResponseEntity<java.lang.Object>
    */
    @ResponseBody
    @ExceptionHandler(value = {MethodArgumentNotValidException.class, BindException.class})
    public ResponseEntity<Object> methodArgumentNotValidHandler(HttpServletRequest request, Exception e) {
        BindingResult bindingResult;
        List<String> messageArr = new ArrayList<>();
        if (e instanceof MethodArgumentNotValidException) {
            //@RequestBody参数校验
            bindingResult = ((MethodArgumentNotValidException) e).getBindingResult();
        } else {
            //@ModelAttribute参数校验
            bindingResult = ((BindException) e).getBindingResult();
        }
        List<ObjectError> allErrors = bindingResult.getAllErrors();
        allErrors.forEach(o -> {
            messageArr.add(o.getDefaultMessage());
        });
        log.error("校验异常：", e);
        return ResponseEntity.ok(ResponseResult.fail(null, HttpStatus.BAD_REQUEST.value(), messageArr.toArray()));
    }

    /**
     * RequestParam参数校验
     * @author Sunjianwang
     * @param e
     * @return org.springframework.http.ResponseEntity<java.lang.Object>
    */
    @ResponseBody
    @ExceptionHandler(value = {ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public ResponseEntity<Object> constraintViolationHandler(Exception e) {
        String field;
        String msg;
        if (e instanceof ConstraintViolationException) {
            ConstraintViolation<?> constraintViolation = ((ConstraintViolationException) e).getConstraintViolations().stream().findFirst().get();
            List<Path.Node> pathList = StreamSupport.stream(constraintViolation.getPropertyPath().spliterator(), false)
                    .collect(Collectors.toList());
            field = pathList.get(pathList.size() - 1).getName();
            msg = constraintViolation.getMessage();
        } else {
            // 这个不是JSR标准返回的异常，要自定义提示文本
            field = ((MissingServletRequestParameterException) e).getParameterName();
            msg = "请求参数异常";
        }
        return ResponseEntity.ok(ResponseResult.fail(null, HttpStatus.BAD_REQUEST.value(),field + msg));
    }
}
