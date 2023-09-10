package com.ujcms.util.security.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.lang.Nullable;

import java.net.URISyntaxException;
import java.util.Map;

/**
 * @author PONY
 */
public class WeixinOauthClient extends OauthClient {
    public WeixinOauthClient(String clientId, String clientSecret, String redirectUri) {
        super(PROVIDER, clientId, clientSecret, redirectUri, DEFAULT_SCOPE);
    }

    @Override
    public String getAuthorizationUri() {
        return "https://open.weixin.qq.com/connect/qrconnect";
    }

    public static final String TOKEN_URI = "https://api.weixin.qq.com/sns/oauth2/access_token";
    public static final String USER_INFO_URI = "https://api.weixin.qq.com/sns/userinfo";

    @Override
    public String getAuthorizationUrl(String state) {
        try {
            URIBuilder builder = new URIBuilder(getAuthorizationUri())
                    .setParameter(RESPONSE_TYPE, RESPONSE_TYPE_CODE)
                    .setParameter(APPID, clientId)
                    .setParameter(REDIRECT_URI, redirectUri);
            if (scope != null) {
                builder.setParameter(SCOPE, scope);
            }
            builder.setParameter(STATE, state);
            return builder.build().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public OauthToken getOauthToken(String code) throws URISyntaxException, JsonProcessingException {
        URIBuilder builder = new URIBuilder(TOKEN_URI);
        builder.setParameter(APPID, clientId);
        builder.setParameter(SECRET, clientSecret);
        builder.setParameter(GRANT_TYPE, AUTHORIZATION_CODE);
        builder.setParameter(CODE, code);
        builder.setParameter(REDIRECT_URI, redirectUri);
        String response = executeHttp(new HttpGet(builder.build()));
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> map = objectMapper.readValue(response, new TypeReference<Map<String, String>>() {
        });
        if (map.get(ACCESS_TOKEN) == null) {
            throw new RuntimeException("Weixin get_access_token error: " + response);
        }
        OauthToken token = new OauthToken();
        token.setProvider(PROVIDER);
        token.setAccessToken(map.get(ACCESS_TOKEN));
        token.setRefreshToken(map.get(REFRESH_TOKEN));
        token.setOpenid(map.get(OPENID));
        token.setUnionid(map.get(UNIONID));
        fillUserInfo(token);
        return token;
    }

    private void fillUserInfo(OauthToken token) throws URISyntaxException, JsonProcessingException {
        URIBuilder builder = new URIBuilder(USER_INFO_URI);
        builder.setParameter(ACCESS_TOKEN, token.getAccessToken());
        builder.setParameter(OPENID, token.getOpenid());
        String response = executeHttp(new HttpGet(builder.build()));
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> map = objectMapper.readValue(response, new TypeReference<Map<String, Object>>() {
        });
        if (map.get(NICKNAME) == null) {
            throw new RuntimeException("Weixin get_userinfo error: " + response);
        }
        token.setNickname((String) map.get(NICKNAME));
        int sex = ((Number) map.get(SEX)).intValue();
        if (sex == 1) {
            token.setGender("m");
        } else if (sex == 2) {
            token.setGender("f");
        } else {
            token.setGender("n");
        }
        token.setAvatarUrl((String) map.get(HEADIMGURL));
        token.setLargeAvatarUrl((String) map.get(HEADIMGURL));
    }

    /**
     * 第三方登录提供者
     */
    public static final String PROVIDER = "weixin";
    /**
     * client_id 在微信里面为 appid
     */
    public static final String APPID = "appid";
    /**
     * client_secret 在微信里面为 secret
     */
    public static final String SECRET = "secret";
    /**
     * 默认获取的权限
     */
    public static final String DEFAULT_SCOPE = "snsapi_login";
    /**
     * 普通用户的标识，对当前开发者帐号唯一
     */
    public static final String OPENID = "openid";
    /**
     * 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的 unionid 是唯一的。
     */
    public static final String UNIONID = "unionid";
    /**
     * 普通用户昵称
     */
    public static final String NICKNAME = "nickname";
    /**
     * 用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），用户没有头像时该项为空
     */
    public static final String HEADIMGURL = "headimgurl";
    /**
     * 普通用户性别，1为男性，2为女性
     */
    public static final String SEX = "sex";
}
