package com.ujcms.cms.core.web.support;

import com.ujcms.util.web.exception.Http403Exception;
import org.springframework.lang.Nullable;

/**
 * 站点无权限异常
 *
 * @author PONY
 */
public class SiteForbiddenException extends Http403Exception {
    public SiteForbiddenException(String code, @Nullable String... args) {
        super(code, args);
    }
}
