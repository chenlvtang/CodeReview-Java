package com.ujcms.cms.core.web.directive;

import com.ujcms.cms.core.service.ChannelService;
import com.ujcms.cms.core.web.support.Directives;
import com.ujcms.cms.core.domain.Article;
import com.ujcms.cms.core.service.ArticleService;
import com.ujcms.util.freemarker.Freemarkers;
import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateException;
import freemarker.template.TemplateModel;

import java.io.IOException;
import java.util.Map;

/**
 * 文章 标签
 *
 * @author PONY
 */
public class ArticleDirective implements TemplateDirectiveModel {
    private static final String ID = "id";

    @SuppressWarnings("unchecked")
    @Override
    public void execute(Environment env, Map params, TemplateModel[] loopVars, TemplateDirectiveBody body)
            throws TemplateException, IOException {
        Freemarkers.requireLoopVars(loopVars);
        Freemarkers.requireBody(body);
        Integer id = Directives.getIntegerRequired(params, ID);

        Article article = articleService.select(id);
        if (article != null) {
            article.getChannel().getPaths().forEach(channelService::fetchFirstData);
        }
        loopVars[0] = env.getObjectWrapper().wrap(article);
        body.render(env.getOut());
    }

    private final ArticleService articleService;
    private final ChannelService channelService;

    public ArticleDirective(ArticleService articleService, ChannelService channelService) {
        this.articleService = articleService;
        this.channelService = channelService;
    }
}