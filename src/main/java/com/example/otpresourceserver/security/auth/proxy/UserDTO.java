package com.example.otpresourceserver.security.auth.proxy;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserDTO {
  private String username;
  private String password;
  private String code;
}