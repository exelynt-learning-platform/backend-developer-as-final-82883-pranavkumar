package com.exelynt.booking.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshRequest(
        @NotBlank(message = "refreshToken is required")
        @Size(max = 200, message = "refreshToken must not exceed 200 characters")
        String refreshToken) {

    @Override
    public String toString() {
        return "RefreshRequest{refreshToken='[PROTECTED]'}";
    }
}
