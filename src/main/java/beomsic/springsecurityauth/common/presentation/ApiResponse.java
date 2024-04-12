package beomsic.springsecurityauth.common.presentation;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
public class ApiResponse<T> {
    private final Integer code;
    private final String message;
    private final T result;

    public ApiResponse(ApiResponseMessage apiResponseMessage) {
        this.code = apiResponseMessage.getCode();
        this.message = apiResponseMessage.getMessage();
        this.result = null;
    }

    public ApiResponse(ApiResponseMessage apiResponseMessage, T result) {
        this.code = apiResponseMessage.getCode();
        this.message = apiResponseMessage.getMessage();
        this.result = result;
    }
}