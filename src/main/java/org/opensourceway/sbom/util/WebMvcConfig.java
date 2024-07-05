package org.opensourceway.sbom.util;


import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;

/**
 * 配置添加拦截器
 */
@Component
public class WebMvcConfig implements WebMvcConfigurer {


    @Resource
    private AuthInterceptor authInterceptor;


    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .excludePathPatterns("/sbom-api/login")
                .excludePathPatterns("/sbom-api/callback")
                .excludePathPatterns("/sbom-api/refreshToken")
                .excludePathPatterns("/sbom-api/addProduct")
                .excludePathPatterns("/sbom-api/publishSbomFile")
                .excludePathPatterns("/sbom-api/querySbomPublishResult/{taskId}")
                .addPathPatterns("/**");
    }
}


