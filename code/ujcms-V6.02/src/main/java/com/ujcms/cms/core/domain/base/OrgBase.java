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
public class OrgBase implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * 数据库表名
     */
    public static final String TABLE_NAME = "org";

    /**
     * 组织ID
     */
    @NotNull
    @Schema(description="组织ID")
    private Integer id = 0;

    /**
     * 上级组织ID
     */
    @Nullable
    @Schema(description="上级组织ID")
    private Integer parentId;

    /**
     * 名称
     */
    @Length(max = 50)
    @NotNull
    @Schema(description="名称")
    private String name = "";

    /**
     * 电话
     */
    @Length(max = 100)
    @Nullable
    @Schema(description="电话")
    private String phone;

    /**
     * 地址
     */
    @Length(max = 300)
    @Nullable
    @Schema(description="地址")
    private String address;

    /**
     * 联系人
     */
    @Length(max = 50)
    @Nullable
    @Schema(description="联系人")
    private String contacts;

    /**
     * 层级
     */
    @NotNull
    @Schema(description="层级")
    private Short depth = 1;

    /**
     * 排序
     */
    @NotNull
    @Schema(description="排序")
    private Integer order = 999999;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    @Nullable
    public Integer getParentId() {
        return parentId;
    }

    public void setParentId(@Nullable Integer parentId) {
        this.parentId = parentId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Nullable
    public String getPhone() {
        return phone;
    }

    public void setPhone(@Nullable String phone) {
        this.phone = phone;
    }

    @Nullable
    public String getAddress() {
        return address;
    }

    public void setAddress(@Nullable String address) {
        this.address = address;
    }

    @Nullable
    public String getContacts() {
        return contacts;
    }

    public void setContacts(@Nullable String contacts) {
        this.contacts = contacts;
    }

    public Short getDepth() {
        return depth;
    }

    public void setDepth(Short depth) {
        this.depth = depth;
    }

    public Integer getOrder() {
        return order;
    }

    public void setOrder(Integer order) {
        this.order = order;
    }
}