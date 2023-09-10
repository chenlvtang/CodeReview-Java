package com.ujcms.cms.core.domain.base;

import io.swagger.v3.oas.annotations.media.Schema;
import java.io.Serializable;
import java.time.OffsetDateTime;
import javax.validation.constraints.NotNull;
import org.hibernate.validator.constraints.Length;
import org.springframework.lang.Nullable;

/**
 * This class was generated by MyBatis Generator.
 *
 * @author MyBatis Generator
 */
public class UserExtBase implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * 数据库表名
     */
    public static final String TABLE_NAME = "user_ext";

    /**
     * 用户ID
     */
    @NotNull
    @Schema(description="用户ID")
    private Integer id = 0;

    /**
     * 真实姓名
     */
    @Length(max = 50)
    @Nullable
    @Schema(description="真实姓名")
    private String realName;

    /**
     * 性别(m:男,f:女,n:保密)
     */
    @Length(max = 1)
    @NotNull
    @Schema(description="性别(m:男,f:女,n:保密)")
    private String gender = "m";

    /**
     * 出生日期
     */
    @Nullable
    @Schema(description="出生日期")
    private OffsetDateTime birthday;

    /**
     * 居住地
     */
    @Length(max = 200)
    @Nullable
    @Schema(description="居住地")
    private String location;

    /**
     * 自我介绍
     */
    @Length(max = 1000)
    @Nullable
    @Schema(description="自我介绍")
    private String bio;

    /**
     * 创建日期
     */
    @NotNull
    @Schema(description="创建日期")
    private OffsetDateTime created = OffsetDateTime.now();

    /**
     * 历史密码(70*24)
     */
    @Length(max = 1000)
    @Nullable
    @Schema(description="历史密码(70*24)")
    private String historyPassword;

    /**
     * 最后登录日期
     */
    @NotNull
    @Schema(description="最后登录日期")
    private OffsetDateTime loginDate = OffsetDateTime.now();

    /**
     * 最后登录IP
     */
    @Length(max = 45)
    @NotNull
    @Schema(description="最后登录IP")
    private String loginIp = "localhost";

    /**
     * 登录次数
     */
    @NotNull
    @Schema(description="登录次数")
    private Integer loginCount = 0;

    /**
     * 登录错误日期
     */
    @NotNull
    @Schema(description="登录错误日期")
    private OffsetDateTime errorDate = OffsetDateTime.now();

    /**
     * 登录错误次数
     */
    @NotNull
    @Schema(description="登录错误次数")
    private Integer errorCount = 0;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    @Nullable
    public String getRealName() {
        return realName;
    }

    public void setRealName(@Nullable String realName) {
        this.realName = realName;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    @Nullable
    public OffsetDateTime getBirthday() {
        return birthday;
    }

    public void setBirthday(@Nullable OffsetDateTime birthday) {
        this.birthday = birthday;
    }

    @Nullable
    public String getLocation() {
        return location;
    }

    public void setLocation(@Nullable String location) {
        this.location = location;
    }

    @Nullable
    public String getBio() {
        return bio;
    }

    public void setBio(@Nullable String bio) {
        this.bio = bio;
    }

    public OffsetDateTime getCreated() {
        return created;
    }

    public void setCreated(OffsetDateTime created) {
        this.created = created;
    }

    @Nullable
    public String getHistoryPassword() {
        return historyPassword;
    }

    public void setHistoryPassword(@Nullable String historyPassword) {
        this.historyPassword = historyPassword;
    }

    public OffsetDateTime getLoginDate() {
        return loginDate;
    }

    public void setLoginDate(OffsetDateTime loginDate) {
        this.loginDate = loginDate;
    }

    public String getLoginIp() {
        return loginIp;
    }

    public void setLoginIp(String loginIp) {
        this.loginIp = loginIp;
    }

    public Integer getLoginCount() {
        return loginCount;
    }

    public void setLoginCount(Integer loginCount) {
        this.loginCount = loginCount;
    }

    public OffsetDateTime getErrorDate() {
        return errorDate;
    }

    public void setErrorDate(OffsetDateTime errorDate) {
        this.errorDate = errorDate;
    }

    public Integer getErrorCount() {
        return errorCount;
    }

    public void setErrorCount(Integer errorCount) {
        this.errorCount = errorCount;
    }
}