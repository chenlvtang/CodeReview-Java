package com.ujcms.cms.core.domain.base;

import io.swagger.v3.oas.annotations.media.Schema;
import java.io.Serializable;
import javax.validation.constraints.NotNull;
import org.hibernate.validator.constraints.Length;
import org.springframework.lang.Nullable;

/**
 * This class was generated by MyBatis Generator.
 *
 * @author MyBatis Generator
 */
public class UserOpenidBase implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * 数据库表名
     */
    public static final String TABLE_NAME = "user_openid";

    /**
     * 用户ID
     */
    @NotNull
    @Schema(description="用户ID")
    private Integer userId = 0;

    /**
     * 提供商
     */
    @Length(max = 20)
    @NotNull
    @Schema(description="提供商")
    private String provider = "";

    /**
     * OPEN ID
     */
    @Length(max = 50)
    @NotNull
    @Schema(description="OPEN ID")
    private String openid = "";

    /**
     * 昵称
     */
    @Length(max = 50)
    @Nullable
    @Schema(description="昵称")
    private String nickname;

    /**
     * 性别(m:男,f:女,n:保密)
     */
    @Length(max = 1)
    @NotNull
    @Schema(description="性别(m:男,f:女,n:保密)")
    private String gender = "m";

    /**
     * 头像URL
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="头像URL")
    private String avatarUrl;

    /**
     * 大头像URL
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="大头像URL")
    private String largeAvatarUrl;

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getOpenid() {
        return openid;
    }

    public void setOpenid(String openid) {
        this.openid = openid;
    }

    @Nullable
    public String getNickname() {
        return nickname;
    }

    public void setNickname(@Nullable String nickname) {
        this.nickname = nickname;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    @Nullable
    public String getAvatarUrl() {
        return avatarUrl;
    }

    public void setAvatarUrl(@Nullable String avatarUrl) {
        this.avatarUrl = avatarUrl;
    }

    @Nullable
    public String getLargeAvatarUrl() {
        return largeAvatarUrl;
    }

    public void setLargeAvatarUrl(@Nullable String largeAvatarUrl) {
        this.largeAvatarUrl = largeAvatarUrl;
    }
}