package com.ujcms.util.web.exception;

import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;

/**
 * 无权限异常
 *
 * @author PONY
 */
public class Http403Exception extends AccessDeniedException implements MessagedException {
    private static final long serialVersionUID = -6637879419165866600L;

    public Http403Exception(String code, @Nullable String... args) {
        super(code);
        this.args = args;
    }

    @Nullable
    @Override
    public String getCode() {
        return getMessage();
    }

    @Nullable
    @Override
    public String[] getArgs() {
        return args;
    }

    @Nullable
    private final String[] args;
}
