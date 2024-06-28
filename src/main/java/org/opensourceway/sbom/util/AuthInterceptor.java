package org.opensourceway.sbom.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 鉴权拦截器
 */
@Configuration
public class AuthInterceptor implements HandlerInterceptor {
    @Autowired
    private JwtUtils jwtUtils;

    private static final Logger logger = LoggerFactory.getLogger(HandlerInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        try {
            //1.获取当前用户的token和refreshtoken信息
            // 获取所有的 cookie
            Cookie[] cookies = request.getCookies();
            if (cookies==null||cookies.length==0){
                JwtUtils.setReturn(request, response, 401, "当前用户没有权限！");
                return false;
            }
            String token = jwtUtils.getCookie(cookies,"token");
            if (!StringUtils.hasText(token)){
                JwtUtils.setReturn(request, response, 401, "当前用户没有权限！");
                return false;
            }
            //2.验证token
           String tokenVerify = jwtUtils.verifyToken(token);
           //如果token过期，使用refreshtoken重新获取token
            if ("timeExpired".equals(tokenVerify)) {
                JwtUtils.setReturn(request, response, 409, "token已经过期，请重新登陆！");
                return false;
            }else if ("validException".equals(tokenVerify)){
                JwtUtils.setReturn(request, response, 401, "token无效，请重新登陆！");
                return false;
            }
            return true;
        } catch (Exception e) {
            logger.error("登录异常：" + e.getMessage());
        }
        JwtUtils.setReturn(request, response, 500, "未知错误！");
        return false;
    }
}
