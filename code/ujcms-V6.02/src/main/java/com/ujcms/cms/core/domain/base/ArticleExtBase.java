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
public class ArticleExtBase implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * 数据库表名
     */
    public static final String TABLE_NAME = "article_ext";

    /**
     * 文章ID
     */
    @NotNull
    @Schema(description="文章ID")
    private Integer id = 0;

    /**
     * 标题
     */
    @Length(max = 150)
    @NotNull
    @Schema(description="标题")
    private String title = "";

    /**
     * 副标题
     */
    @Length(max = 150)
    @Nullable
    @Schema(description="副标题")
    private String subtitle;

    /**
     * 完整标题
     */
    @Length(max = 150)
    @Nullable
    @Schema(description="完整标题")
    private String fullTitle;

    /**
     * 别名
     */
    @Length(max = 160)
    @Nullable
    @Schema(description="别名")
    private String alias;

    /**
     * 转向链接地址
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="转向链接地址")
    private String linkUrl;

    /**
     * 是否新窗口打开
     */
    @NotNull
    @Schema(description="是否新窗口打开")
    private Boolean targetBlank = false;

    /**
     * SEO关键词
     */
    @Length(max = 150)
    @Nullable
    @Schema(description="SEO关键词")
    private String seoKeywords;

    /**
     * 摘要
     */
    @Length(max = 1000)
    @Nullable
    @Schema(description="摘要")
    private String seoDescription;

    /**
     * 作者
     */
    @Length(max = 50)
    @Nullable
    @Schema(description="作者")
    private String author;

    /**
     * 编辑
     */
    @Length(max = 50)
    @Nullable
    @Schema(description="编辑")
    private String editor;

    /**
     * 来源
     */
    @Length(max = 50)
    @Nullable
    @Schema(description="来源")
    private String source;

    /**
     * 下线日期
     */
    @Nullable
    @Schema(description="下线日期")
    private OffsetDateTime offlineDate;

    /**
     * 置顶时间
     */
    @Nullable
    @Schema(description="置顶时间")
    private OffsetDateTime stickyDate;

    /**
     * 图片
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="图片")
    private String image;

    /**
     * 视频
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="视频")
    private String video;

    /**
     * 原视频
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="原视频")
    private String videoOrig;

    /**
     * 视频时长
     */
    @Nullable
    @Schema(description="视频时长")
    private Integer videoDuration;

    /**
     * 音频
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="音频")
    private String audio;

    /**
     * 原音频
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="原音频")
    private String audioOrig;

    /**
     * 音频时长
     */
    @Nullable
    @Schema(description="音频时长")
    private Integer audioDuration;

    /**
     * 文件
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="文件")
    private String file;

    /**
     * 文件名称
     */
    @Length(max = 150)
    @Nullable
    @Schema(description="文件名称")
    private String fileName;

    /**
     * 文件大小
     */
    @Nullable
    @Schema(description="文件大小")
    private Long fileLength;

    /**
     * 文库
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="文库")
    private String doc;

    /**
     * 文库原文档
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="文库原文档")
    private String docOrig;

    /**
     * 文库名称
     */
    @Length(max = 150)
    @Nullable
    @Schema(description="文库名称")
    private String docName;

    /**
     * 文库大小
     */
    @Nullable
    @Schema(description="文库大小")
    private Long docLength;

    /**
     * 独立模板
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="独立模板")
    private String articleTemplate;

    /**
     * 是否允许评论
     */
    @NotNull
    @Schema(description="是否允许评论")
    private Boolean allowComment = true;

    /**
     * 静态页文件
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="静态页文件")
    private String staticFile;

    /**
     * 手机端静态页文件
     */
    @Length(max = 255)
    @Nullable
    @Schema(description="手机端静态页文件")
    private String mobileStaticFile;

    /**
     * 创建日期
     */
    @NotNull
    @Schema(description="创建日期")
    private OffsetDateTime created = OffsetDateTime.now();

    /**
     * 修改日期
     */
    @Nullable
    @Schema(description="修改日期")
    private OffsetDateTime modified;

    /**
     * 流程实例ID
     */
    @Length(max = 64)
    @Nullable
    @Schema(description="流程实例ID")
    private String processInstanceId;

    /**
     * 退回原因
     */
    @Length(max = 300)
    @Nullable
    @Schema(description="退回原因")
    private String rejectReason;

    /**
     * 是否百度推送
     */
    @NotNull
    @Schema(description="是否百度推送")
    private Boolean baiduPush = false;

    /**
     * 编辑器类型(1:富文本编辑器,2:Markdown编辑器)
     */
    @NotNull
    @Schema(description="编辑器类型(1:富文本编辑器,2:Markdown编辑器)")
    private Short editorType = 1;

    /**
     * 图片集JSON
     */
    @Nullable
    @Schema(description="图片集JSON")
    private String imageListJson;

    /**
     * 文件集JSON
     */
    @Nullable
    @Schema(description="文件集JSON")
    private String fileListJson;

    /**
     * 正文
     */
    @Nullable
    @Schema(description="正文")
    private String text;

    /**
     * Markdown正文
     */
    @Nullable
    @Schema(description="Markdown正文")
    private String markdown;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    @Nullable
    public String getSubtitle() {
        return subtitle;
    }

    public void setSubtitle(@Nullable String subtitle) {
        this.subtitle = subtitle;
    }

    @Nullable
    public String getFullTitle() {
        return fullTitle;
    }

    public void setFullTitle(@Nullable String fullTitle) {
        this.fullTitle = fullTitle;
    }

    @Nullable
    public String getAlias() {
        return alias;
    }

    public void setAlias(@Nullable String alias) {
        this.alias = alias;
    }

    @Nullable
    public String getLinkUrl() {
        return linkUrl;
    }

    public void setLinkUrl(@Nullable String linkUrl) {
        this.linkUrl = linkUrl;
    }

    public Boolean getTargetBlank() {
        return targetBlank;
    }

    public void setTargetBlank(Boolean targetBlank) {
        this.targetBlank = targetBlank;
    }

    @Nullable
    public String getSeoKeywords() {
        return seoKeywords;
    }

    public void setSeoKeywords(@Nullable String seoKeywords) {
        this.seoKeywords = seoKeywords;
    }

    @Nullable
    public String getSeoDescription() {
        return seoDescription;
    }

    public void setSeoDescription(@Nullable String seoDescription) {
        this.seoDescription = seoDescription;
    }

    @Nullable
    public String getAuthor() {
        return author;
    }

    public void setAuthor(@Nullable String author) {
        this.author = author;
    }

    @Nullable
    public String getEditor() {
        return editor;
    }

    public void setEditor(@Nullable String editor) {
        this.editor = editor;
    }

    @Nullable
    public String getSource() {
        return source;
    }

    public void setSource(@Nullable String source) {
        this.source = source;
    }

    @Nullable
    public OffsetDateTime getOfflineDate() {
        return offlineDate;
    }

    public void setOfflineDate(@Nullable OffsetDateTime offlineDate) {
        this.offlineDate = offlineDate;
    }

    @Nullable
    public OffsetDateTime getStickyDate() {
        return stickyDate;
    }

    public void setStickyDate(@Nullable OffsetDateTime stickyDate) {
        this.stickyDate = stickyDate;
    }

    @Nullable
    public String getImage() {
        return image;
    }

    public void setImage(@Nullable String image) {
        this.image = image;
    }

    @Nullable
    public String getVideo() {
        return video;
    }

    public void setVideo(@Nullable String video) {
        this.video = video;
    }

    @Nullable
    public String getVideoOrig() {
        return videoOrig;
    }

    public void setVideoOrig(@Nullable String videoOrig) {
        this.videoOrig = videoOrig;
    }

    @Nullable
    public Integer getVideoDuration() {
        return videoDuration;
    }

    public void setVideoDuration(@Nullable Integer videoDuration) {
        this.videoDuration = videoDuration;
    }

    @Nullable
    public String getAudio() {
        return audio;
    }

    public void setAudio(@Nullable String audio) {
        this.audio = audio;
    }

    @Nullable
    public String getAudioOrig() {
        return audioOrig;
    }

    public void setAudioOrig(@Nullable String audioOrig) {
        this.audioOrig = audioOrig;
    }

    @Nullable
    public Integer getAudioDuration() {
        return audioDuration;
    }

    public void setAudioDuration(@Nullable Integer audioDuration) {
        this.audioDuration = audioDuration;
    }

    @Nullable
    public String getFile() {
        return file;
    }

    public void setFile(@Nullable String file) {
        this.file = file;
    }

    @Nullable
    public String getFileName() {
        return fileName;
    }

    public void setFileName(@Nullable String fileName) {
        this.fileName = fileName;
    }

    @Nullable
    public Long getFileLength() {
        return fileLength;
    }

    public void setFileLength(@Nullable Long fileLength) {
        this.fileLength = fileLength;
    }

    @Nullable
    public String getDoc() {
        return doc;
    }

    public void setDoc(@Nullable String doc) {
        this.doc = doc;
    }

    @Nullable
    public String getDocOrig() {
        return docOrig;
    }

    public void setDocOrig(@Nullable String docOrig) {
        this.docOrig = docOrig;
    }

    @Nullable
    public String getDocName() {
        return docName;
    }

    public void setDocName(@Nullable String docName) {
        this.docName = docName;
    }

    @Nullable
    public Long getDocLength() {
        return docLength;
    }

    public void setDocLength(@Nullable Long docLength) {
        this.docLength = docLength;
    }

    @Nullable
    public String getArticleTemplate() {
        return articleTemplate;
    }

    public void setArticleTemplate(@Nullable String articleTemplate) {
        this.articleTemplate = articleTemplate;
    }

    public Boolean getAllowComment() {
        return allowComment;
    }

    public void setAllowComment(Boolean allowComment) {
        this.allowComment = allowComment;
    }

    @Nullable
    public String getStaticFile() {
        return staticFile;
    }

    public void setStaticFile(@Nullable String staticFile) {
        this.staticFile = staticFile;
    }

    @Nullable
    public String getMobileStaticFile() {
        return mobileStaticFile;
    }

    public void setMobileStaticFile(@Nullable String mobileStaticFile) {
        this.mobileStaticFile = mobileStaticFile;
    }

    public OffsetDateTime getCreated() {
        return created;
    }

    public void setCreated(OffsetDateTime created) {
        this.created = created;
    }

    @Nullable
    public OffsetDateTime getModified() {
        return modified;
    }

    public void setModified(@Nullable OffsetDateTime modified) {
        this.modified = modified;
    }

    @Nullable
    public String getProcessInstanceId() {
        return processInstanceId;
    }

    public void setProcessInstanceId(@Nullable String processInstanceId) {
        this.processInstanceId = processInstanceId;
    }

    @Nullable
    public String getRejectReason() {
        return rejectReason;
    }

    public void setRejectReason(@Nullable String rejectReason) {
        this.rejectReason = rejectReason;
    }

    public Boolean getBaiduPush() {
        return baiduPush;
    }

    public void setBaiduPush(Boolean baiduPush) {
        this.baiduPush = baiduPush;
    }

    public Short getEditorType() {
        return editorType;
    }

    public void setEditorType(Short editorType) {
        this.editorType = editorType;
    }

    @Nullable
    public String getImageListJson() {
        return imageListJson;
    }

    public void setImageListJson(@Nullable String imageListJson) {
        this.imageListJson = imageListJson;
    }

    @Nullable
    public String getFileListJson() {
        return fileListJson;
    }

    public void setFileListJson(@Nullable String fileListJson) {
        this.fileListJson = fileListJson;
    }

    @Nullable
    public String getText() {
        return text;
    }

    public void setText(@Nullable String text) {
        this.text = text;
    }

    @Nullable
    public String getMarkdown() {
        return markdown;
    }

    public void setMarkdown(@Nullable String markdown) {
        this.markdown = markdown;
    }
}