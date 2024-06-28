package org.opensourceway.sbom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ImportResource;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@ImportResource(locations = {"classpath:spring-batch/sbom-read-job.xml"})
@EnableTransactionManagement
@EnableAsync
public class SbomManagerApplication extends SpringBootServletInitializer {

    private static final Logger logger = LoggerFactory.getLogger(SbomManagerApplication.class);

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(SbomManagerApplication.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(SbomManagerApplication.class, args);
        logger.info("Sbom service has started");
    }
}
