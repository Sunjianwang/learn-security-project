package learn.config.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Getter
@AllArgsConstructor
public enum ResponseStatus {

    SUCCESS(200, "成功"),
    FAIL(500, "服务器错误"),

    HTTP_STATUS_200(200, "成功"),
    HTTP_STATUS_400(400, "请求错误"),
    HTTP_STATUS_401(401, "没有进行认证"),
    HTTP_STATUS_403(403, "没有权限访问"),
    HTTP_STATUS_500(500, "服务器错误");

    public static final List<ResponseStatus> HTTP_STATUS_ALL = Collections.unmodifiableList(
            Arrays.asList(HTTP_STATUS_200, HTTP_STATUS_400, HTTP_STATUS_401, HTTP_STATUS_403, HTTP_STATUS_500
            ));

    /**
     * 状态码
     */
    private final Integer responseCode;

    /**
     * 描述
     */
    private final String description;

}
