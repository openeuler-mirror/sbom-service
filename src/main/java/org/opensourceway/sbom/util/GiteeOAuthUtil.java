package org.opensourceway.sbom.util;

import com.google.gson.reflect.TypeToken;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.HashMap;

/**
 * 功能描述
 *
 * @author ly
 * @since 2021-6-22
 */
@Component
public class GiteeOAuthUtil {
    private static final Logger logger = LoggerFactory.getLogger(GiteeOAuthUtil.class);

    @Value("${gitee.auth.url}")
    private String giteeAuthUrl;

    @Value("${gitee.token.url}")
    private String giteeTokenUrl;

    @Value("${gitee.oauth.client.id}")
    private String clientId;

    @Value("${gitee.oauth.client.secret}")
    private String clientSecret;

    @Value("${sbom.redirectUrl}")
    private String redirectUrl;

    @Value("${gitee.infoUrl}")
    private  String infoUrl;

    /**
     * 获取gitee登陆地址
     *
     * @return
     */
    public String getGiteeAuthUrl() {
        return String.format(giteeAuthUrl, clientId, redirectUrl);
    }


    /**
     * 调用码云接口 获得access token
     *
     * @param code 码云返回的识别码
     * @return HashMap
     */
    public HashMap<String, String> getToken(String code) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Content-Type", "application/json;charset=UTF-8");
        HashMap<String, String> params = new HashMap<>();
        params.put("client_secret", clientSecret);
        String content = JsonParseUtils.toJson(params);
        //根据gitee返回code获取accesstoken
        String format = String.format(giteeTokenUrl, code, clientId, redirectUrl, clientSecret);
        OkHttpClient client = new OkHttpClient().newBuilder()
                .build();
        MediaType mediaType = MediaType.parse("application/json");
        RequestBody data = RequestBody.create(mediaType, content);
        Request request = new Request.Builder()
                .url(format)
                .method("POST", data)
                .addHeader("Content-Type", "application/json")
                .build();
        HashMap<String, String> res = new HashMap<>();
        try {
            Response response = client.newCall(request).execute();
            String result = response.body().string();
            res = JsonParseUtils.fromJson(result, new TypeToken<HashMap<String, String>>() {
            }.getType());
        } catch (IOException e) {
            logger.error("get access_token from gitee error");
            res.put("error_message", "get access_token from gitee error");
        }
        return res;
    }

    /**
     * 获取登录者的信息
     *
     * @param accessToken 码云token
     * @return HashMap
     */
    public  HashMap<String, String> getInfo(String accessToken) {
        HashMap<String, String> res = new HashMap<>();
        String url = String.format(infoUrl, accessToken);
        OkHttpClient client = new OkHttpClient().newBuilder()
                .build();
        Request request = new Request.Builder()
                .url(url)
                .method("GET", null)
                .build();
        try {
            Response response = client.newCall(request).execute();
            String result = response.body().string();
            res = JsonParseUtils.fromJson(result, new TypeToken<HashMap<String, String>>() {
            }.getType());
        } catch (IOException e) {
            logger.error("get info from gitee error");
            res.put("error_message", "get info from gitee error");
        }
        return res;
    }

    /**
     * 设置cookie
     *
     * @param value
     * @param age
     * @return
     */
    public Cookie getCookie(String name, String value, int age) {
        Cookie cookie = new Cookie(name, value);
        cookie.setDomain("sbom-service.osinfra.cn");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(age);
        cookie.setPath("/");
        return cookie;
    }
}
