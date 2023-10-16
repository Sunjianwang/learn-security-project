package learn.config.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class ResponseResult<T> {
    /**
     * 返回时间戳
     */
    private long timestamp;

    /**
     * 响应码
     */
    private Integer status;

    /**
     * 响应信息
     */
    private Object message;

    /**
     * 响应数据
     */
    private T data;

    /**
     * 响应成功-返回默认信息
     * @author Sunjianwang
     * @return zhifou.config.response.ResponseResult<T>
    */
    public static <T> ResponseResult<T> success() {
        return success(null);
    }

    /**
     * 响应成功-自定义返回数据
     * @author Sunjianwang
     * @param data 返回数据
     * @return zhifou.config.response.ResponseResult<T>
    */
    public static <T> ResponseResult<T> success(T data) {
        return ResponseResult.<T>builder().data(data)
                .message(ResponseStatus.SUCCESS.getDescription())
                .status(HttpStatus.OK.value())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * 响应成功-自定义返回数据和信息
     * @author Sunjianwang
     * @param data 返回数据
     * @param message 返回信息
     * @return zhifou.config.response.ResponseResult<T>
    */
    public static <T> ResponseResult<T> success(T data,String message){
        return ResponseResult.<T>builder()
                .data(data)
                .message(message)
                .status(HttpStatus.OK.value())
                .build();
    }

    /**
     * 响应失败-默认信息
     * @author Sunjianwang
     * @return zhifou.config.response.ResponseResult<T>
     */
    public static <T> ResponseResult<T> fail() {
        return ResponseResult.<T>builder()
                .data(null)
                .status(ResponseStatus.HTTP_STATUS_500.getResponseCode())
                .message(ResponseStatus.HTTP_STATUS_500.getDescription())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * 响应失败-自定义信息
     * @author Sunjianwang
     * @param message 响应信息
     * @return zhifou.config.response.ResponseResult<T>
    */
    public static <T> ResponseResult<T> fail(Object message) {
        return ResponseResult.<T>builder()
                .data(null)
                .status(ResponseStatus.HTTP_STATUS_500.getResponseCode())
                .message(ResponseStatus.HTTP_STATUS_500.getDescription())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * 响应失败-自定义返回数据和信息
     * @author Sunjianwang
     * @param data 数据
     * @param message 信息
     * @return zhifou.config.response.ResponseResult<T>
    */
    public static <T> ResponseResult<T> fail(T data, Object message) {
        return ResponseResult.<T>builder().data(data)
                .message(message)
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * 响应失败-自定义返回数据、状态码和信息
     * @author Sunjianwang
     * @param data 数据信息
     * @param httpState 状态码
     * @param message 错误信息
     * @return zhifou.config.response.ResponseResult<T>
    */
    public static <T> ResponseResult<T> fail(T data,Integer httpState,Object message) {
        return ResponseResult.<T>builder().data(data)
                .message(message)
                .status(httpState)
                .timestamp(System.currentTimeMillis())
                .build();
    }

}
