package learn.exception;

import lombok.Data;
import org.springframework.http.HttpStatus;

/**
 * //TODO
 *
 * @author Sunjianwang
 * @version 1.0
 */
@Data
public class GlobalException extends RuntimeException{

    private HttpStatus status;
    private String message;

    public GlobalException(String message) {
        super(message);
        this.message = message;
    }

    public GlobalException(HttpStatus status, String message) {
        this.status = status;
        this.message = message;
    }

    public GlobalException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
        this.message = message;
    }
}
