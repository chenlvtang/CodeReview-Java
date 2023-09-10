package com.ujcms.cms.core.service.args;

import com.ujcms.util.query.BaseQueryArgs;
import org.springframework.lang.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * 组织查询参数
 *
 * @author PONY
 */
public class AttachmentArgs extends BaseQueryArgs {
    public AttachmentArgs siteId(@Nullable Integer siteId) {
        if (siteId != null) {
            queryMap.put("EQ_siteId_Int", siteId);
        }
        return this;
    }

    public static AttachmentArgs of() {
        return of(new HashMap<>(16));
    }

    public static AttachmentArgs of(Map<String, Object> queryMap) {
        return new AttachmentArgs(queryMap);
    }

    private AttachmentArgs(Map<String, Object> queryMap) {
        super(queryMap);
    }
}
