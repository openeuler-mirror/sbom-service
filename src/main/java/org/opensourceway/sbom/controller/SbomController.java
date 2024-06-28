package org.opensourceway.sbom.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.api.repo.RepoService;
import org.opensourceway.sbom.api.sbom.SbomService;
import org.opensourceway.sbom.dao.SbomUserRepository;
import org.opensourceway.sbom.enums.HttpConstants;
import org.opensourceway.sbom.enums.PermissionConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.echarts.Graph;
import org.opensourceway.sbom.model.entity.InfoModel;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductStatistics;
import org.opensourceway.sbom.model.entity.ProductVulRef;
import org.opensourceway.sbom.model.entity.SbomUser;
import org.opensourceway.sbom.model.exception.AddProductException;
import org.opensourceway.sbom.model.pojo.request.sbom.AddProductRequest;
import org.opensourceway.sbom.model.pojo.request.sbom.PublishSbomRequest;
import org.opensourceway.sbom.model.pojo.request.sbom.QuerySbomPackagesRequest;
import org.opensourceway.sbom.model.pojo.request.sbom.SbomUserVo;
import org.opensourceway.sbom.model.pojo.response.sbom.PublishResultResponse;
import org.opensourceway.sbom.model.pojo.response.sbom.PublishSbomResponse;
import org.opensourceway.sbom.model.pojo.response.sbom.UpstreamAndPatchInfoResponse;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.BinaryManagementVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.CopyrightVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.LicenseVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackagePurlVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageStatisticsVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageWithStatisticsVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PageVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.ProductConfigVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.VulCountVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.VulnerabilityVo;
import org.opensourceway.sbom.model.spec.ExternalPurlRefCondition;
import org.opensourceway.sbom.util.GiteeOAuthUtil;
import org.opensourceway.sbom.util.JsonParseUtils;
import org.opensourceway.sbom.util.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@SuppressWarnings("rawtypes")
@Controller
@RequestMapping(path = "/sbom-api")
public class SbomController {

    private static final Logger logger = LoggerFactory.getLogger(SbomController.class);

    @Autowired
    private SbomService sbomService;

    @Autowired
    private RepoService repoService;

    @Autowired
    private GiteeOAuthUtil giteeOAuthUtil;

    @Autowired
    private SbomUserRepository sbomUserRepository;

    @Value("${sbom.info}")
    private String sbomInfo;

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/publishSbomFile")
    public @ResponseBody ResponseEntity publishSbomFile(@RequestBody PublishSbomRequest publishSbomRequest) {
        logger.info("publish sbom file request:{}", publishSbomRequest);
        PublishSbomResponse response = new PublishSbomResponse();

        UUID taskId;
        try {
            taskId = sbomService.publishSbom(publishSbomRequest);
        } catch (Exception e) {
            logger.error("publish sbom failed", e);
            response.setSuccess(Boolean.FALSE);
            response.setErrorInfo("publish sbom failed!");
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
        }

        response.setSuccess(Boolean.TRUE);
        response.setTaskId(taskId);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @GetMapping("/querySbomPublishResult/{taskId}")
    public @ResponseBody ResponseEntity querySbomPublishResult(@PathVariable("taskId") String taskId) {
        logger.info("query sbom publish result, taskId:{}", taskId);
        UUID uuid;
        try {
            uuid = UUID.fromString(taskId);
        } catch (IllegalArgumentException e) {
            logger.error("String to UUID failed", e);
            return ResponseEntity.status(HttpStatus.OK).body(new PublishResultResponse(Boolean.FALSE,
                    Boolean.FALSE,
                    e.getMessage(),
                    null));
        }

        PublishResultResponse result = sbomService.getSbomPublishResult(uuid);
        logger.info("query sbom publish resul:{}", result);
        return ResponseEntity.status(HttpStatus.OK).body(result);
    }

    @PostMapping("/uploadSbomFile")
    public @ResponseBody ResponseEntity uploadSbomFile(HttpServletRequest request, @RequestParam String productName) throws IOException {//HttpServletRequest request
        MultipartFile file = ((MultipartHttpServletRequest) request).getFile("uploadFileName");
        if (file == null || file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("upload file is empty");
        }
        String fileName = file.getOriginalFilename();
        logger.info("upload {}`s sbom file name: {}, file length: {}", productName, fileName, file.getBytes().length);

        try {
            sbomService.readSbomFile(productName, fileName, file.getBytes());
        } catch (Exception e) {
            logger.error("uploadSbomFile failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("uploadSbomFile failed");
        }

        return ResponseEntity.status(HttpStatus.ACCEPTED).body("Success");
    }

    @Deprecated
    @RequestMapping("/exportSbomFile")
    public void exportSbomFile(HttpServletRequest request, HttpServletResponse response, @RequestParam String productName, @RequestParam String spec,
                               @RequestParam String specVersion, @RequestParam String format) throws IOException {
        logger.info("download original sbom file productName:{}, use spec:{}, specVersion:{}, format:{}",
                productName,
                spec,
                specVersion,
                format);
        byte[] rawSbom = null;
        String errorMsg = null;

        try {
            var sbom = sbomService.writeSbomFile(productName, spec, specVersion, format);
            rawSbom = sbom.getValue();
        } catch (Exception e) {
            logger.error("exportSbomFile failed", e);
            errorMsg = "exportSbomFile failed";
        }

        var filename = "%s-%s-sbom.%s".formatted(URLEncoder.encode(productName, StandardCharsets.UTF_8), spec, format);
        downloadSbom(request, response, filename, rawSbom, errorMsg);
    }

    @RequestMapping("/exportSbom")
    public void exportSbom(HttpServletRequest request, HttpServletResponse response, @RequestParam String productName, @RequestParam String spec,
                           @RequestParam String specVersion, @RequestParam String format) throws IOException {
        logger.info("download sbom metadata productName:{}, use spec:{}, specVersion:{}, format:{}",
                productName,
                spec,
                specVersion,
                format);
        byte[] sbom = null;
        String errorMsg = null;

        try {
            sbom = sbomService.writeSbom(productName, spec, specVersion, format);
        } catch (Exception e) {
            logger.error("export sbom metadata failed", e);
            errorMsg = "export sbom metadata failed";
        }
        String filename = "%s-%s-sbom.%s".formatted(URLEncoder.encode(productName, StandardCharsets.UTF_8), spec, format);
        downloadSbom(request, response, filename, sbom, errorMsg);
    }

    @Deprecated
    @PostMapping("/querySbomPackages")
    public @ResponseBody ResponseEntity querySbomPackagesDeprecated(@RequestParam("productName") String productName,
                                                                    @RequestParam(value = "packageName", required = false) String packageName,
                                                                    @RequestParam(value = "isExactly", required = false) Boolean isExactly,
                                                                    @RequestParam(required = false) String vulSeverity,
                                                                    @RequestParam(required = false) Boolean noLicense,
                                                                    @RequestParam(required = false) Boolean multiLicense,
                                                                    @RequestParam(required = false) Boolean isLegalLicense,
                                                                    @RequestParam(required = false) String licenseId,
                                                                    @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
                                                                    @RequestParam(name = "size", required = false, defaultValue = "15") Integer size) {
        var req = new QuerySbomPackagesRequest();
        req.setProductName(productName);
        req.setPackageName(packageName);
        req.setExactly(isExactly);
        req.setVulSeverity(vulSeverity);
        req.setNoLicense(noLicense);
        req.setMultiLicense(multiLicense);
        req.setLegalLicense(isLegalLicense);
        req.setLicenseId(licenseId);
        req.setPage(page);
        req.setSize(size);
        return querySbomPackages(req);
    }

    public @ResponseBody ResponseEntity querySbomPackages(@RequestBody QuerySbomPackagesRequest req) {
        logger.info("query sbom packages request: {}", req);
        PageVo<PackageWithStatisticsVo> packagesPage = sbomService.getPackageInfoByNameForPage(req);
        logger.info("query sbom packages result:{}", packagesPage);
        return ResponseEntity.status(HttpStatus.OK).body(packagesPage);
    }

    @GetMapping("/querySbomPackages/{productName}/{packageName}/{isExactly}")
    public @ResponseBody ResponseEntity getPackagesInfoByName(@PathVariable("productName") String productName,
                                                              @PathVariable("packageName") String packageName,
                                                              @PathVariable(value = "isExactly") boolean isExactly) {
        logger.info("query sbom packages by productName:{}, packageName:{}, isExactly:{}", productName, packageName, isExactly);
        List<PackageWithStatisticsVo> packagesList = sbomService.queryPackageInfoByName(productName, packageName, isExactly);

        logger.info("query sbom packages result:{}", packagesList);
        return ResponseEntity.status(HttpStatus.OK).body(packagesList);
    }

    @GetMapping("/querySbomPackage/{packageId}")
    public @ResponseBody ResponseEntity getPackageInfoById(@PathVariable("packageId") String packageId) {
        logger.info("query sbom package by packageId:{}", packageId);
        Package packageInfo;
        try {
            packageInfo = sbomService.queryPackageInfoById(packageId);
        } catch (RuntimeException e) {
            logger.error("query sbom package error:", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query sbom package error");
        }

        logger.info("query sbom package result:{}", packageInfo);
        if (packageInfo == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("the queried package doesn't exist");
        }
        return ResponseEntity.status(HttpStatus.OK).body(packageInfo);
    }

    @GetMapping("/queryPackageBinaryManagement/{packageId}/{binaryType}")
    public @ResponseBody ResponseEntity queryPackageBinaryManagement(@PathVariable("packageId") String packageId,
                                                                     @PathVariable("binaryType") String binaryType) {
        logger.info("query package binary management by packageId:{}, binaryType:{}", packageId, binaryType);

        BinaryManagementVo result = sbomService.queryPackageBinaryManagement(packageId, binaryType);

        logger.info("query package binary management result:{}", result);
        return ResponseEntity.status(HttpStatus.OK).body(result);
    }


    @PostMapping("/querySbomPackagesByBinary")
    public @ResponseBody ResponseEntity queryPackageInfoByBinary(@RequestParam("productName") String productName,
                                                                 @RequestParam("binaryType") String binaryType,
                                                                 @RequestParam("type") String type,
                                                                 @RequestParam(name = "namespace", required = false) String namespace,
                                                                 @RequestParam(name = "name") String name,
                                                                 @RequestParam(name = "version", required = false) String version,
                                                                 @RequestParam(required = false) String startVersion,
                                                                 @RequestParam(required = false) String endVersion,
                                                                 @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
                                                                 @RequestParam(name = "size", required = false, defaultValue = "15") Integer size) {
        logger.info("query package info by productName:{}, binaryType:{}, type:{}, namespace:{}, name:{}, version:{}, " +
                        "startVersion:{}, endVersion: {}",
                productName, binaryType, type, namespace, name, version, startVersion, endVersion);

        PageVo<PackagePurlVo> queryResult;

        try {
            ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                    .productName(productName)
                    .binaryType(binaryType)
                    .type(type)
                    .namespace(namespace)
                    .name(name)
                    .version(version)
                    .startVersion(startVersion)
                    .endVersion(endVersion)
                    .build();
            Pageable pageable = PageRequest.of(page, size);

            queryResult = sbomService.queryPackageInfoByBinaryViaSpec(condition, pageable);
        } catch (Exception e) {
            logger.error("query sbom packages failed.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query sbom packages failed.");
        }

        logger.info("query sbom packages result:{}", queryResult == null ? 0 : queryResult.getTotalElements());
        return ResponseEntity.status(HttpStatus.OK).body(queryResult);
    }

    @GetMapping("/queryProductType")
    public @ResponseBody ResponseEntity queryProductType() {
        logger.info("query product type");
        List<String> queryResult;

        try {
            queryResult = sbomService.queryProductType();
        } catch (Exception e) {
            logger.error("query product type failed.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query product type failed.");
        }

        logger.info("query product type result:{}", queryResult);
        return ResponseEntity.status(HttpStatus.OK).body(queryResult);
    }

    @GetMapping("/queryProductConfig/{productType}")
    public @ResponseBody ResponseEntity queryProductConfigByProductType(@PathVariable("productType") String productType) {
        logger.info("query product config by productType:{}", productType);
        ProductConfigVo queryResult;

        try {
            queryResult = sbomService.queryProductConfigByProductType(productType);
        } catch (Exception e) {
            logger.error("query product config failed.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query product config failed.");
        }

        logger.info("query product config result: {}", queryResult);
        return ResponseEntity.status(HttpStatus.OK).body(queryResult);
    }

    @PostMapping("/queryProduct/{productType}")
    public @ResponseBody ResponseEntity queryProductByFullAttributes(@PathVariable("productType") String productType,
                                                                     @RequestBody Map<String, String> attributes) {
        logger.info("query product info by productType:{}, attributes:{}", productType, attributes);
        attributes.put("productType", productType);

        try {
            Product queryResult = sbomService.queryProductByFullAttributes(attributes);

            if (queryResult == null) {
                logger.info("query product info result is null");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("product is not exist");
            } else {
                logger.info("query product info result:{}", queryResult);
                return ResponseEntity.status(HttpStatus.OK).body(queryResult);
            }
        } catch (Exception e) {
            logger.error("query product info failed.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query product info failed.");
        }
    }

    @GetMapping("/queryPackageVulnerability/{packageId}")
    public @ResponseBody ResponseEntity queryVulnerabilityByPackageId(@PathVariable("packageId") String packageId,
                                                                      @RequestParam(required = false) String severity,
                                                                      @RequestParam(required = false) String vulId,
                                                                      @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
                                                                      @RequestParam(name = "size", required = false, defaultValue = "15") Integer size) {
        logger.info("query package vulnerability by packageId: {}, severity: {}, vulId: {}", packageId, severity, vulId);
        PageVo<VulnerabilityVo> vulnerabilities;
        Pageable pageable = PageRequest.of(page, size);
        try {
            vulnerabilities = sbomService.queryPackageVulnerability(packageId, severity, vulId, pageable);
        } catch (Exception e) {
            logger.error("query package vulnerability error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query package vulnerability error");
        }

        logger.info("query package vulnerability result:{}", Objects.isNull(vulnerabilities) ? 0 : vulnerabilities.getTotalElements());
        return ResponseEntity.status(HttpStatus.OK).body(vulnerabilities);
    }

    @GetMapping("/queryLicenseUniversalApi")
    public @ResponseBody
    ResponseEntity queryLicense(@RequestParam(name = "productName") String productName,
                                @RequestParam(name = "license", required = false) String license,
                                @RequestParam(name = "isLegal", required = false) Boolean isLegal,
                                @RequestParam(name = "orderBy", required = false, defaultValue = "licenseId") String orderBy,
                                @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
                                @RequestParam(name = "size", required = false, defaultValue = "15") Integer size) throws Exception {
        logger.info("query package License for productName by universal api: {}", productName);
        PageVo<LicenseVo> licenses;
        Pageable pageable = "count".equals(orderBy) ?
                PageRequest.of(page, size).withSort(Sort.by(Sort.Order.desc(orderBy))) : PageRequest.of(page, size).withSort(Sort.by(Sort.Order.asc(orderBy)));
        licenses = sbomService.queryLicense(productName, license, isLegal, pageable);
        return ResponseEntity.status(HttpStatus.OK).body(licenses);
    }

    @GetMapping("/queryPackageLicenseAndCopyright/{packageId}")
    public @ResponseBody
    ResponseEntity queryLicenseByPackageId(@PathVariable("packageId") String packageId) {
        logger.info("query package License by packageId: {}", packageId);
        Map<String, List> licenseAndCopyright = new HashMap<>();
        List<LicenseVo> licenses;
        List<CopyrightVo> copyrights;
        try {
            licenses = sbomService.queryLicenseByPackageId(packageId);
            copyrights = sbomService.queryCopyrightByPackageId(packageId);
            licenseAndCopyright.put("licenseContent", licenses);
            licenseAndCopyright.put("copyrightContent", copyrights);
        } catch (Exception e) {
            logger.error("query package license error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query package license error");
        }

        return ResponseEntity.status(HttpStatus.OK).body(licenseAndCopyright);
    }

    @PostMapping("/uploadSbomTraceData")
    public @ResponseBody
    ResponseEntity uploadSbomTraceData(HttpServletRequest request, @RequestParam String productName) throws IOException {//HttpServletRequest request
        MultipartFile file = ((MultipartHttpServletRequest) request).getFile("uploadFileName");
        if (file == null || file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("upload file is empty");
        }
        String fileName = file.getOriginalFilename();
        logger.info("upload {}'s sbom trace data: {}, file length: {}", productName, file.getOriginalFilename(), file.getBytes().length);

        try {
            sbomService.persistSbomFromTraceData(productName, fileName, file.getInputStream());
        } catch (Exception e) {
            logger.error("failed to uploadSbomTraceData", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("failed to uploadSbomTraceData");
        }

        return ResponseEntity.status(HttpStatus.ACCEPTED).body("Success");
    }

    @GetMapping("/queryProductStatistics/{*productName}")
    public @ResponseBody ResponseEntity queryProductStatisticsByProductName(@PathVariable String productName) {
        productName = productName.substring(1);
        logger.info("query product statistics by product name: {}", productName);
        ProductStatistics productStatistics;
        try {
            productStatistics = sbomService.queryProductStatistics(productName);
        } catch (Exception e) {
            logger.error("query product statistics error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query product statistics error");
        }

        if (Objects.isNull(productStatistics)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("product statistics doesn't exist");
        }

        logger.info("query product statistics result: {}", productStatistics);
        return ResponseEntity.status(HttpStatus.OK).body(productStatistics);
    }

    @GetMapping("/queryProductVulTrend/{*productName}")
    public @ResponseBody ResponseEntity queryProductVulTrendByProductNameAndTimeRange(@PathVariable String productName,
                                                                                      @RequestParam(required = false, defaultValue = "0") Long startTimestamp,
                                                                                      @RequestParam(required = false, defaultValue = "0") Long endTimestamp) {
        productName = productName.substring(1);
        logger.info("query product vulnerability trend by product name: {}, time range: [{}, {}]", productName, startTimestamp, endTimestamp);
        List<VulCountVo> vulCountVos;
        try {
            vulCountVos = sbomService.queryProductVulTrend(productName, startTimestamp, endTimestamp);
        } catch (Exception e) {
            logger.error("query product vulnerability trend error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query product vulnerability trend error");
        }

        logger.info("query product vulnerability trend result: {}", vulCountVos);
        return ResponseEntity.status(HttpStatus.OK).body(vulCountVos);
    }

    @GetMapping("/queryPackageStatistics/{packageId}")
    public @ResponseBody ResponseEntity queryPackageStatisticsByPackageId(@PathVariable("packageId") String packageId) {
        logger.info("query package statistics by packageId: {}", packageId);
        PackageStatisticsVo vo;
        try {
            vo = sbomService.queryPackageStatisticsByPackageId(packageId);
        } catch (Exception e) {
            logger.error("query package statistics error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query package statistics error");
        }

        if (Objects.isNull(vo)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("the queried package doesn't exist");
        }

        logger.info("query package statistics result: {}", vo);
        return ResponseEntity.status(HttpStatus.OK).body(vo);
    }

    @Deprecated
    private Boolean isFetchRepoMetaRunning = Boolean.FALSE;

    @GetMapping("/fetchOpenEulerRepoMeta")
    @Deprecated
    public @ResponseBody ResponseEntity fetchOpenEulerRepoMeta() {
        if (isFetchRepoMetaRunning) {
            logger.warn("start manual launch fetch-openEuler-repo-meta, has job running");
            return ResponseEntity.status(HttpStatus.OK).body("Running");
        } else {
            this.isFetchRepoMetaRunning = Boolean.TRUE;
            logger.info("start manual launch fetch-openEuler-repo-meta");
        }

        long start = System.currentTimeMillis();
        try {
            Set<RepoInfoVo> result = repoService.fetchOpenEulerRepoMeta();
            logger.info("fetch-openEuler-repo-meta result size:{}", result.size());
        } catch (Exception e) {
            logger.error("manual launch fetch-openEuler-repo-meta job failed", e);
        } finally {
            this.isFetchRepoMetaRunning = Boolean.FALSE;
        }

        logger.info("finish manual launch fetch-openEuler-repo-meta job, coast:{} ms", System.currentTimeMillis() - start);
        return ResponseEntity.status(HttpStatus.OK).body("OK");
    }

    @GetMapping("/queryVulnerability/{*productName}")
    public @ResponseBody ResponseEntity queryVulnerability(@PathVariable String productName,
                                                           @RequestParam(required = false) String severity,
                                                           @RequestParam(required = false) String packageId,
                                                           @RequestParam(required = false) String vulId,
                                                           @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
                                                           @RequestParam(name = "size", required = false, defaultValue = "15") Integer size) {
        productName = productName.substring(1);
        logger.info("query vulnerability by product name: {}, severity: {}, packageId: {}, vulId: {}", productName, severity, packageId, vulId);

        PageVo<VulnerabilityVo> vulnerabilities;
        Pageable pageable = PageRequest.of(page, size);
        try {
            vulnerabilities = sbomService.queryVulnerability(productName, packageId, severity, vulId, pageable);
        } catch (Exception e) {
            logger.error("query vulnerability error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("query vulnerability error");
        }

        logger.info("query vulnerability result: {}", Objects.isNull(vulnerabilities) ? 0 : vulnerabilities.getTotalElements());
        return ResponseEntity.status(HttpStatus.OK).body(vulnerabilities);
    }

    @GetMapping("/queryVulImpact/{*productName}")
    public @ResponseBody ResponseEntity queryVulImpact(@PathVariable String productName, @RequestParam String vulId) {
        productName = productName.substring(1);
        logger.info("queryVulImpact by productName: {}, vulId: {}", productName, vulId);

        Graph graph;
        try {
            graph = sbomService.queryVulImpact(productName, vulId);
        } catch (Exception e) {
            logger.error("queryVulImpact error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("queryVulImpact error");
        }

        logger.info("queryVulImpact result has {} nodes, {} edges", graph.getNodes().size(), graph.getEdges().size());
        return ResponseEntity.status(HttpStatus.OK).body(graph);
    }

    @GetMapping("/queryUpstreamAndPatchInfo/{packageId}")
    public @ResponseBody ResponseEntity queryUpstreamAndPatchInfo(@PathVariable("packageId") String packageId) {
        logger.info("query upstream and patch info by packageId:{}", packageId);
        UpstreamAndPatchInfoResponse response;
        try {
            response = repoService.queryUpstreamAndPatchInfo(packageId);
        } catch (Exception e) {
            logger.error("query upstream and patch info by packageId:{}, error:", packageId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("queryUpstreamAndPatchInfo error");
        }

        logger.info("query upstream and patch info by packageId:{}, result size:{} {}",
                packageId,
                CollectionUtils.size(response.getUpstreamList()),
                CollectionUtils.size(response.getPatchList()));
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/addProduct")
    public @ResponseBody ResponseEntity queryProductByFullAttributes(@RequestBody AddProductRequest addProductRequest) {
        logger.info("add product: {}", addProductRequest);

        try {
            sbomService.addProduct(addProductRequest);
            logger.info("successfully add product: {}", addProductRequest.getProductName());
            return ResponseEntity.status(HttpStatus.OK).body("Success");
        } catch (AddProductException e) {
            logger.error("failed to add product.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        } catch (Exception e) {
            logger.error("failed to add product.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("failed to add product.");
        }
    }

    @RequestMapping("/exportPackageSbom")
    public void exportPackageSbom(HttpServletRequest request, HttpServletResponse response,
                                  @RequestParam String productName, @RequestParam String packageName, @RequestParam String packageVersion,
                                  @RequestParam String spec, @RequestParam String specVersion, @RequestParam String format)
            throws IOException {
        logger.info("download package sbom metadata productName: {}, packageName: {}, packageVersion: {}, " +
                "use spec: {}, specVersion: {}, format: {}", productName, packageName, packageVersion, spec, specVersion, format);
        byte[] sbom = null;
        String errorMsg = null;

        try {
            sbom = sbomService.writePackageSbom(productName, packageName, packageVersion, spec, specVersion, format);
        } catch (Exception e) {
            logger.error("export package sbom metadata failed", e);
            errorMsg = "export package sbom metadata failed";
        }

        String fileName = "%s-%s-%s-%s-sbom.%s".formatted(
                URLEncoder.encode(productName, StandardCharsets.UTF_8), packageName, packageVersion, spec, format);
        downloadSbom(request, response, fileName, sbom, errorMsg);
    }

    @RequestMapping("/exportAllPackageSbom")
    public void exportAllPackageSbom(HttpServletRequest request, HttpServletResponse response,
                                     @RequestParam String productName, @RequestParam String spec, @RequestParam String specVersion,
                                     @RequestParam String format) throws IOException {
        logger.info("download all package sbom metadata, productName: {}, use spec: {}, specVersion: {}, format: {}",
                productName, spec, specVersion, format);
        byte[] allPkgSbom = null;
        String errorMsg = null;

        try {
            allPkgSbom = sbomService.writeAllPackageSbom(productName, spec, specVersion, format);
        } catch (Exception e) {
            logger.error("export all package sbom metadata failed", e);
            errorMsg = "export all package sbom metadata failed";
        }

        String filename = "%s-%s-sbom.tar.gz".formatted(URLEncoder.encode(productName, StandardCharsets.UTF_8), spec);
        downloadSbom(request, response, filename, allPkgSbom, errorMsg);
    }

    private void downloadSbom(HttpServletRequest request, HttpServletResponse response,
                              String filename, byte[] content, String errorMsg) throws IOException {
        response.reset();

        if (Objects.isNull(content)) {
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType("text/plain");
            response.addHeader("Content-Length", String.valueOf(errorMsg.getBytes(StandardCharsets.UTF_8).length));
            //CORS
            String origin = request.getHeader("origin");
            if (SbomConstants.ALLOW_ORIGINS.contains(origin)) {
                response.addHeader("Access-Control-Allow-Origin", origin);
                response.addHeader("Access-Control-Allow-Methods", "POST");
                response.addHeader("Access-Control-Allow-Headers", "Content-Type");
                response.addHeader("Access-Control-Expose-Headers", "Content-Disposition");
            }

            OutputStream outputStream = new BufferedOutputStream(response.getOutputStream());
            outputStream.write(errorMsg.getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
        } else {
            var sbomWithVerification = sbomService.generateVerificationAndTar(filename, content);

            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment;filename=%s.tar.gz".formatted(filename));
            response.addHeader("Content-Length", String.valueOf(sbomWithVerification.length));

            OutputStream outputStream = new BufferedOutputStream(response.getOutputStream());
            outputStream.write(sbomWithVerification);
            outputStream.flush();
        }
    }

    @GetMapping("/queryProductVulImpact/{*productName}")
    public @ResponseBody ResponseEntity queryVulImpact(@PathVariable String productName,
                                                       @RequestParam(name = "vulId", required = false) String vulId,
                                                       @RequestParam(name = "issueId", required = false) String issueId,
                                                       @RequestParam(name = "vulStatus", required = false) String vulStatus,
                                                       @RequestParam(name = "issueStatus", required = false) String issueStatus,
                                                       @RequestParam(name = "rpmName", required = false) String rpmName,
                                                       @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
                                                       @RequestParam(name = "size", required = false, defaultValue = "15") Integer size) {
        productName = productName.substring(1);
        logger.info("queryVulImpact by productName: {}", productName);

        PageVo<ProductVulRef> productVulRefs;
        Pageable pageable = PageRequest.of(page, size);
        try {
            productVulRefs = sbomService.queryProductVulImpact(productName, vulId, issueId, vulStatus, issueStatus, rpmName, pageable);
        } catch (Exception e) {
            logger.error("queryProductVulImpact error: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("queryProductVulImpact error");
        }
        return ResponseEntity.status(HttpStatus.OK).body(productVulRefs);
    }

    /**
     * 返回gitee回调地址
     *
     * @return
     * @throws IOException
     */
    @GetMapping("/login")
    public ResponseEntity login() {
        logger.info("login info --------------------------------------");
        String giteeLoginAuthUrl = giteeOAuthUtil.getGiteeAuthUrl();
        HashMap<String, String> reponse = new HashMap<>();
        reponse.put("code", "200");
        reponse.put("authUrl", giteeLoginAuthUrl);
        return ResponseEntity.status(HttpStatus.OK).body(JsonParseUtils.toJson(reponse));
    }


    /**
     * gitee回调地址
     *
     * @return
     * @throws IOException
     */
    @GetMapping("/callback")
    private void callBack(HttpServletRequest request, HttpServletResponse response) {
        logger.info("callBack info --------------------------------------");
        String code = request.getParameter("code");
        //获取gitee的access_token
        HashMap<String, String> token = giteeOAuthUtil.getToken(code);
        String accessToken = token.get(HttpConstants.ACCESS_TOKEN);
        if (StringUtils.isNotEmpty(accessToken)) {
            //根据accessToken获取gitee用户信息
            HashMap<String, String> info = giteeOAuthUtil.getInfo(accessToken); // 通过gitee token获取账号信息
            //只有安全委员会成员才有资格访问sbom系统
            List<SbomUser> sbomUserList = sbomUserRepository.findSbomUser(info.get(PermissionConstants.LOGIN));
            if (CollectionUtils.isEmpty(sbomUserList)) {
                response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                response.addHeader("location", sbomInfo);
                JwtUtils.setReturn(request, response, 302, "当前用户没有权限！");
                return;
            }
            if (StringUtils.isNotEmpty(info.get(PermissionConstants.NAME))) {
                InfoModel infoModel = new InfoModel();
                infoModel.setId(info.get(PermissionConstants.ID));
                infoModel.setName(info.get(PermissionConstants.NAME));
                infoModel.setLogin(info.get(PermissionConstants.LOGIN));
                infoModel.setAvatarUrl(info.get(PermissionConstants.AVATAR_URL));
                infoModel.setSub("gitee");
                //设置token有效期180分钟
                String tokenValue = jwtUtils.getToken(infoModel, 240);
                //设置过期时间
                Cookie cookie = giteeOAuthUtil.getCookie("token", tokenValue, 60 * 60 * 24);
                response.addCookie(cookie);
                response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                response.addHeader("location", sbomInfo);
                JwtUtils.setReturn(request, response, 302, "callback success-----------" + tokenValue);
            } else {
                JwtUtils.setReturn(request, response, 401, "errorMessage gitee code wrong or expired");
            }
            return;
        }
    }


    /**
     * 退出登录
     *
     * @return
     * @throws IOException
     */
    @GetMapping("/logout")
    private void logout(HttpServletRequest request, HttpServletResponse response) {
        logger.info("logout info --------------------------------------");
        //清理token和refreshToken
        Cookie cookie = giteeOAuthUtil.getCookie("token", "", 0);
        Cookie refreshCookie = giteeOAuthUtil.getCookie("refreshToken", "", 0);
        response.addCookie(cookie);
        response.addCookie(refreshCookie);
        JwtUtils.setReturn(request, response, 200, "logout success ");
    }

    /**
     * 注册用户
     *
     * @return
     * @throws IOException
     */
    @PostMapping("/registerSbomUser")
    private ResponseEntity registerSbomUser(@RequestBody SbomUserVo sbomUserVo) {
        logger.info("registerSbomUser info --------------------------------------");
        return sbomService.registerSbomUser(sbomUserVo);
    }

    /**
     * 返回用户基本信息
     *
     * @return
     * @throws IOException
     */
    @GetMapping("/getInfo")
    private ResponseEntity getInfo(HttpServletRequest request) {
        logger.info("getInfo info --------------------------------------");
        Cookie[] cookies = request.getCookies();
        String token = jwtUtils.getCookie(cookies, "token");
        //验证token
        String id = JwtUtils.getClaimByName(token, PermissionConstants.ID).as(String.class);
        String name = JwtUtils.getClaimByName(token, PermissionConstants.NAME).as(String.class);
        String login = JwtUtils.getClaimByName(token, PermissionConstants.LOGIN).as(String.class);
        String sub = JwtUtils.getClaimByName(token, PermissionConstants.SUB).as(String.class);
        String avatar_url = JwtUtils.getClaimByName(token, PermissionConstants.AVATAR_URL).as(String.class);
        InfoModel infoModel = new InfoModel();
        infoModel.setId(id);
        infoModel.setName(name);
        infoModel.setLogin(login);
        infoModel.setSub(sub);
        infoModel.setAvatarUrl(avatar_url);
        HashMap<String, Object> response = new HashMap<>();
        response.put("code", 200);
        response.put("data", infoModel);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }


    /**
     * 刷新token,同时刷新token和refreshtoken
     *
     * @return
     * @throws IOException
     */
    @GetMapping("/refreshToken")
    private void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        //判断refreshToken是否合法，是否过期，如果过期需要重新登录
        Cookie[] cookies = request.getCookies();
        String refreshToken = jwtUtils.getCookie(cookies, "refreshToken");
        String refreshTokenVerify = jwtUtils.verifyToken(refreshToken);
        if ("validException".equals(refreshTokenVerify) || "timeExpired".equals(refreshTokenVerify)) {
            JwtUtils.setReturn(request, response, 401, "refreshToken 验证失败，请重新登录");
            return;
        }

        //判断token是否过期，如果过期，生成新的token和判断refreshtoken是否合法返回前端
        String token = jwtUtils.getCookie(cookies, "token");
        String tokenVerify = jwtUtils.verifyToken(token);
        if ("validException".equals(tokenVerify)) {
            JwtUtils.setReturn(request, response, 500, "token不合法!");
            return;
        } else if ("timeExpired".equals(tokenVerify)) {
            logger.info("token 过期，重新刷新token---------------");
        } else {
            JwtUtils.setReturn(request, response, 500, "token有效请不要重复刷新!");
            return;
        }
        //验证token
        String id = JwtUtils.getClaimByName(token, PermissionConstants.ID).as(String.class);
        String name = JwtUtils.getClaimByName(token, PermissionConstants.NAME).as(String.class);
        String login = JwtUtils.getClaimByName(token, PermissionConstants.LOGIN).as(String.class);
        String sub = JwtUtils.getClaimByName(token, PermissionConstants.SUB).as(String.class);
        String avatar_url = JwtUtils.getClaimByName(token, PermissionConstants.AVATAR_URL).as(String.class);
        InfoModel infoModel = new InfoModel();
        infoModel.setId(id);
        infoModel.setName(name);
        //设置默认有效期为1天
        String refreshTokenValue = jwtUtils.getToken(infoModel, 60*24);
        infoModel.setLogin(login);
        infoModel.setSub(sub);
        infoModel.setAvatarUrl(avatar_url);
        //设置token有效期240分钟
        String tokenValue = jwtUtils.getToken(infoModel, 240);
        //设置过期时间
        Cookie cookie = giteeOAuthUtil.getCookie("token", tokenValue, 60 * 60 * 3);
        Cookie refreshCookie = giteeOAuthUtil.getCookie("refreshToken", refreshTokenValue, 60 * 60 * 3);
        response.addCookie(cookie);
        response.addCookie(refreshCookie);
        JwtUtils.setReturn(request, response, 200, "刷新token和refreshToken成功！------------" + tokenValue + "---------------" + refreshTokenValue);
        return;
    }
}
