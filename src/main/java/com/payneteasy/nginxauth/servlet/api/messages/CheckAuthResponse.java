package com.payneteasy.nginxauth.servlet.api.messages;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Data
@FieldDefaults(makeFinal = true, level = PRIVATE)
@Builder
public class CheckAuthResponse {
    boolean success;
    String  errorMessage;
    int     status;
    String  errorId;
}
