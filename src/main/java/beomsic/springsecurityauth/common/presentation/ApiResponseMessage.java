package beomsic.springsecurityauth.common.presentation;

import lombok.Getter;

@Getter
public enum ApiResponseMessage {

    SUCCESS_REQUEST(200, "API 요청이 성공했습니다."),
    INVALID_REQUEST(201, "잘못된 요청입니다."),
    UNAUTHORIZED_REQUEST(401, "인증에 실패한 요청입니다."),
    UNAUTHENTICATED_REQUEST(403, "인가에 실패한 요청입니다."),
    SERVER_ERROR(500, "에러가 발생했습니다.");

    Integer code;
    String message;

    ApiResponseMessage(Integer code, String message) {
        this.code = code;
        this.message = message;
    }
}
