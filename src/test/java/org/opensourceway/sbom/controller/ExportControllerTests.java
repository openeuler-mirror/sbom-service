package org.opensourceway.sbom.controller;


import org.apache.commons.collections4.CollectionUtils;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.SbomManagerApplication;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.model.cyclonedx.Component;
import org.opensourceway.sbom.model.cyclonedx.CycloneDXDocument;
import org.opensourceway.sbom.model.cyclonedx.ExternalReference;
import org.opensourceway.sbom.model.cyclonedx.ExternalReferenceType;
import org.opensourceway.sbom.model.cyclonedx.Patch;
import org.opensourceway.sbom.model.spdx.FileType;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.model.spdx.RelationshipType;
import org.opensourceway.sbom.model.spdx.SpdxDocument;
import org.opensourceway.sbom.model.spdx.SpdxExternalReference;
import org.opensourceway.sbom.model.spdx.SpdxFile;
import org.opensourceway.sbom.model.spdx.SpdxPackage;
import org.opensourceway.sbom.model.spdx.SpdxRelationship;
import org.opensourceway.sbom.utils.Mapper;
import org.opensourceway.sbom.utils.SbomApplicationContextHolder;
import org.opensourceway.sbom.utils.TestCommon;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.StringUtils;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
public class ExportControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void downloadSbomFileFailedNoSbom() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/exportSbomFile")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME + ".iso")
                        .param("spec", "spdx")
                        .param("specVersion", "2.2")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("exportSbomFile failed")));
    }

    @Test
    public void downloadSbomFileFailedNoSpec() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/exportSbomFile")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "spdx")
                        .param("specVersion", "2.3")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("exportSbomFile failed"));
    }

    @Test
    public void downloadSbomFileSuccess() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/exportSbomFile")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "spdx")
                        .param("specVersion", "2.2")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void exportSbomFailedNoSbom() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME + ".iso")
                        .param("spec", "spdx")
                        .param("specVersion", "2.2")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("export sbom metadata failed")));
    }

    @Test
    public void exportCycloneDXSbomFailedNoSbom() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME + ".iso")
                        .param("spec", "cyclonedx")
                        .param("specVersion", "1.4")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("export sbom metadata failed")));
    }


    @Test
    public void exportSbomFailedNoSpec() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "spdx")
                        .param("specVersion", "2.3")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("export sbom metadata failed"));
    }

    @Test
    public void exportCycloneDXSbomFailedNoSpec() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "cyclonedx")
                        .param("specVersion", "1.5")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("export sbom metadata failed"));
    }

    @Test
    public void exportSbomJsonSuccess() throws Exception {
        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "spdx")
                        .param("specVersion", "2.2")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_PRODUCT_NAME + "-spdx-sbom.json.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_PRODUCT_NAME + "-spdx-sbom.json");
        SpdxDocument spdxDocument = Mapper.jsonSbomMapper.readValue(content, SpdxDocument.class);
        TestCommon.assertSpdxDocument(spdxDocument);
    }

    @Test
    public void exportCycloneDXSbomJsonSuccess() throws Exception {

        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "cyclonedx")
                        .param("specVersion", "1.4")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_PRODUCT_NAME + "-cyclonedx-sbom.json.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_PRODUCT_NAME + "-cyclonedx-sbom.json");
        CycloneDXDocument cycloneDXDocument = Mapper.jsonSbomMapper.readValue(content, CycloneDXDocument.class);
        TestCommon.assertCycloneDXDocument(cycloneDXDocument);
    }

    @Test
    public void exportSbomYamlSuccess() throws Exception {
        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "spdx")
                        .param("specVersion", "2.2")
                        .param("format", "yaml")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_PRODUCT_NAME + "-spdx-sbom.yaml.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_PRODUCT_NAME + "-spdx-sbom.yaml");
        SpdxDocument spdxDocument = Mapper.yamlSbomMapper.readValue(content, SpdxDocument.class);
        TestCommon.assertSpdxDocument(spdxDocument);
    }

    @Test
    public void exportCycloneDXSbomYamlSuccess() throws Exception {

        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "cyclonedx")
                        .param("specVersion", "1.4")
                        .param("format", "yaml")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_PRODUCT_NAME + "-cyclonedx-sbom.yaml.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_PRODUCT_NAME + "-cyclonedx-sbom.yaml");
        CycloneDXDocument cycloneDXDocument = Mapper.yamlSbomMapper.readValue(content, CycloneDXDocument.class);
        TestCommon.assertCycloneDXDocument(cycloneDXDocument);
    }

    @Test
    public void exportSbomXmlSuccess() throws Exception {
        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "spdx")
                        .param("specVersion", "2.2")
                        .param("format", "xml")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_PRODUCT_NAME + "-spdx-sbom.xml.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_PRODUCT_NAME + "-spdx-sbom.xml");
        SpdxDocument spdxDocument = Mapper.xmlSbomMapper.readValue(content, SpdxDocument.class);
        TestCommon.assertSpdxDocument(spdxDocument);
    }

    @Test
    public void exportCycloneDXSbomXmlSuccess() throws Exception {

        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("spec", "cyclonedx")
                        .param("specVersion", "1.4")
                        .param("format", "xml")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_PRODUCT_NAME + "-cyclonedx-sbom.xml.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_PRODUCT_NAME + "-cyclonedx-sbom.xml");
        CycloneDXDocument cycloneDXDocument = Mapper.xmlSbomMapper.readValue(content, CycloneDXDocument.class);
        TestCommon.assertCycloneDXDocument(cycloneDXDocument);
    }

    @Test
    public void exportSbomJsonForUpstreamAndPatch() throws Exception {
        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("spec", "spdx")
                        .param("specVersion", "2.2")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_REPODATA_PRODUCT_NAME + "-spdx-sbom.json.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_REPODATA_PRODUCT_NAME + "-spdx-sbom.json");
        SpdxDocument spdxDocument = Mapper.jsonSbomMapper.readValue(content, SpdxDocument.class);

        Optional<SpdxPackage> hivePkgOptional = spdxDocument.getPackages().stream()
                .filter(tempPkg -> StringUtils.endsWithIgnoreCase("SPDXRef-rpm-hive-3.1.2", tempPkg.getSpdxId()))
                .findFirst();
        assertThat(hivePkgOptional.isPresent()).isTrue();
        SpdxPackage hivePkg = hivePkgOptional.get();

        List<SpdxExternalReference> upstreamList = hivePkg.getExternalRefs()
                .stream()
                .filter(tempRef -> tempRef.referenceCategory() == ReferenceCategory.SOURCE_MANAGER)
                .sorted(Comparator.comparing(SpdxExternalReference::referenceLocator))
                .toList();
        assertThat(CollectionUtils.size(upstreamList)).isEqualTo(2);
        assertThat(upstreamList.get(0).referenceCategory()).isEqualTo(ReferenceCategory.SOURCE_MANAGER);
        assertThat(upstreamList.get(0).referenceType()).isEqualTo(ReferenceType.URL);
        assertThat(upstreamList.get(0).referenceLocator()).isEqualTo("http://hive.apache.org/");
        assertThat(upstreamList.get(1).referenceLocator()).isEqualTo("https://gitee.com/src-openeuler/hive/tree/openEuler-22.03-LTS/");

        List<SpdxRelationship> patchRelationshipList = spdxDocument.getRelationships()
                .stream()
                .filter(relationship -> relationship.relationshipType() == RelationshipType.PATCH_APPLIED
                        && StringUtils.endsWithIgnoreCase("SPDXRef-rpm-hive-3.1.2", relationship.relatedSpdxElement()))
                .toList();
        assertThat(CollectionUtils.size(patchRelationshipList)).isEqualTo(3);

        List<SpdxFile> patchFileList = spdxDocument.getFiles()
                .stream()
                .filter(file -> file.fileTypes().get(0) == FileType.SOURCE && StringUtils.startsWithIgnoreCase(file.spdxId(), "hive-"))
                .toList();
        assertThat(CollectionUtils.size(patchRelationshipList)).isEqualTo(3);

        assertThat(StringUtils.endsWithIgnoreCase(patchFileList.get(0).spdxId(), patchRelationshipList.get(0).spdxElementId())).isTrue();
        assertThat(StringUtils.endsWithIgnoreCase(patchFileList.get(1).spdxId(), patchRelationshipList.get(1).spdxElementId())).isTrue();
        assertThat(StringUtils.endsWithIgnoreCase(patchFileList.get(2).spdxId(), patchRelationshipList.get(2).spdxElementId())).isTrue();

        assertThat(patchFileList.get(0).filename()).isEqualTo("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test1.patch");
        assertThat(patchFileList.get(2).filename()).isEqualTo("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test3.patch");
    }


    @Test
    public void exportCycloneDXSbomJsonForUpstreamAndPatch() throws Exception {
        MvcResult mvcResult = this.mockMvc
                .perform(post("/sbom-api/exportSbom")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("spec", "cyclonedx")
                        .param("specVersion", "1.4")
                        .param("format", "json")
                        .contentType(MediaType.ALL)
                        .accept(MediaType.APPLICATION_OCTET_STREAM))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment;filename=" + TestConstants.SAMPLE_REPODATA_PRODUCT_NAME + "-cyclonedx-sbom.json.tar.gz"))
                .andReturn();
        String content = TestCommon.extractSbomFromTar(mvcResult.getResponse().getContentAsByteArray(),
                TestConstants.SAMPLE_REPODATA_PRODUCT_NAME + "-cyclonedx-sbom.json");
        CycloneDXDocument cycloneDXDocument = Mapper.jsonSbomMapper.readValue(content, CycloneDXDocument.class);

        Optional<Component> hivePkgOptional = cycloneDXDocument.getComponents().stream()
                .filter(tempPkg -> StringUtils.endsWithIgnoreCase("SPDXRef-rpm-hive-3.1.2", tempPkg.getBomRef()))
                .findFirst();
        assertThat(hivePkgOptional.isPresent()).isTrue();
        Component hivePkg = hivePkgOptional.get();

        List<ExternalReference> upstreamList = hivePkg.getExternalReferences()
                .stream()
                .filter(tempRef -> tempRef.getType() == ExternalReferenceType.VCS)
                .toList();
        assertThat(CollectionUtils.size(upstreamList)).isEqualTo(2);
        assertThat(upstreamList.get(0).getUrl()).isEqualTo("http://hive.apache.org/");
        assertThat(upstreamList.get(1).getUrl()).isEqualTo("https://gitee.com/src-openeuler/hive/tree/openEuler-22.03-LTS/");

        List<Patch> patchRelationshipList = hivePkg.getPedigree().getPatches();
        assertThat(CollectionUtils.size(patchRelationshipList)).isEqualTo(3);

//        List<SpdxFile> patchFileList = spdxDocument.getFiles()
//                .stream()
//                .filter(file -> file.fileTypes().get(0) == FileType.SOURCE && StringUtils.startsWithIgnoreCase(file.spdxId(), "hive-"))
//                .toList();
//        assertThat(CollectionUtils.size(patchRelationshipList)).isEqualTo(3);

//        assertThat(StringUtils.endsWithIgnoreCase(patchFileList.get(0).spdxId(), patchRelationshipList.get(0).spdxElementId())).isTrue();
//        assertThat(StringUtils.endsWithIgnoreCase(patchFileList.get(1).spdxId(), patchRelationshipList.get(1).spdxElementId())).isTrue();
//        assertThat(StringUtils.endsWithIgnoreCase(patchFileList.get(2).spdxId(), patchRelationshipList.get(2).spdxElementId())).isTrue();

        assertThat(patchRelationshipList.get(0).getDiff().getUrl()).isEqualTo("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test1.patch");
        assertThat(patchRelationshipList.get(2).getDiff().getUrl()).isEqualTo("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test3.patch");
    }
}

