package org.opensourceway.sbom.clients.license;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.io.CloseMode;
import org.opensourceway.sbom.api.license.LicenseClient;
import org.opensourceway.sbom.model.pojo.response.license.ComplianceResponse;
import org.opensourceway.sbom.model.pojo.response.license.LicenseInfo;
import org.opensourceway.sbom.model.pojo.response.license.LicensesJson;
import org.opensourceway.sbom.utils.Mapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.http.codec.json.Jackson2JsonDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.unit.DataSize;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class LicenseClientImpl implements LicenseClient {

    private static final Logger logger = LoggerFactory.getLogger(LicenseClientImpl.class);

    @Value("${compliance3.api.url}")
    private String defaultBaseUrl;

    @Value("${spdx.license.url}")
    private String licenseInfoBaseUrl;

    @Value("${spring.codec.max-in-memory-size}")
    private String maxInMemorySize;

    private WebClient createWebClient(String defaultBaseUrl) {
        ExchangeStrategies strategies = ExchangeStrategies.builder()
                .codecs(codecs -> codecs.defaultCodecs().maxInMemorySize((int) DataSize.parse(maxInMemorySize).toBytes()))
                .build();
        return WebClient.builder()
                .baseUrl(defaultBaseUrl)
                .exchangeStrategies(strategies)
                .build();
    }

    private WebClient createWebClientForPlainText(String defaultBaseUrl) {
        final int size = 1024 * 1024 * 1024;
        final ExchangeStrategies strategies = ExchangeStrategies.builder().codecs(configurer -> {
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            configurer.defaultCodecs().maxInMemorySize(size);
            configurer.customCodecs().register(new Jackson2JsonDecoder(mapper, MimeTypeUtils.parseMimeType(MediaType.TEXT_PLAIN_VALUE)));
        }).build();
        return WebClient.builder()
                .baseUrl(defaultBaseUrl)
                .exchangeStrategies(strategies)
                .build();
    }

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    // get licenses from api by purl
    @Override
    public ComplianceResponse[] getComplianceResponse(List<String> coordinates) throws JsonProcessingException {
        String licenseListStr = Mapper.jsonMapper.writeValueAsString(coordinates);
        WebClient client = createWebClient(defaultBaseUrl);
        MultipartBodyBuilder builder = new MultipartBodyBuilder();
        builder.part("purl", licenseListStr);

        Mono<ComplianceResponse[]> mono = client.post()
                .uri("/lic")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(builder.build())
                .retrieve()
                .bodyToMono(ComplianceResponse[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));

        return mono.block();
    }

    // get a json which has the info and url for all the licenses
    @Override
    public Map<String, LicenseInfo> getLicensesInfo() {
        WebClient client = createWebClientForPlainText(licenseInfoBaseUrl);
        LicensesJson licensesJson = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/spdx/license-list-data/master/json/licenses.json")
                        .build()
                )
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(LicensesJson.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)))
                .block();
        return ObjectUtils.isEmpty(licensesJson) ? Map.of() :
                licensesJson.getLicenses().stream().collect(Collectors.toMap(LicenseInfo::getLicenseId, Function.identity()));
    }

    // request api to scan the licenses in repo
    @Override
    public void scanLicenseFromPurl(String purl) throws Exception {
        HttpPost httpPost;
        CloseableHttpClient httpClient = null;
        try {
            httpPost = new HttpPost(defaultBaseUrl + "/doSca");

            MultipartEntityBuilder builder = MultipartEntityBuilder.create();
            builder.addTextBody("url", purl, ContentType.MULTIPART_FORM_DATA)
                    .addTextBody("async", "True", ContentType.MULTIPART_FORM_DATA);
            httpPost.setEntity(builder.build());

            httpClient = HttpClients.createDefault();

            CloseableHttpResponse response = httpClient.execute(httpPost);
            if (response.getCode() != HttpStatus.SC_OK) {
                logger.error("The response for scan license request is not 200 with purl {}.", purl);
                throw new RuntimeException();
            }

        } finally {
            if (httpClient != null) {
                httpClient.close(CloseMode.IMMEDIATE);
            }
        }

    }
}
