package org.opensourceway.sbom.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.enums.SbomSpecification;

import java.io.IOException;
import java.util.HashMap;

public class SbomMapperUtil {

    @SuppressWarnings("unchecked")
    public static <T> T readDocument(SbomFormat format, Class<?> documentClass, byte[] fileContent) throws IOException {
        if (format == SbomFormat.JSON) {
            return fromJson(fileContent, (Class<T>) documentClass);
        }
        if (format == SbomFormat.XML) {
            return fromXml(fileContent, (Class<T>) documentClass);
        }
        if (format == SbomFormat.YAML) {
            return fromYaml(fileContent, (Class<T>) documentClass);
        }
        if (format == SbomFormat.RDF) {
            return fromRdf(fileContent, (Class<T>) documentClass);
        }
        throw new RuntimeException("invalid sbom file format %s".formatted(format.name()));
    }

    public static SbomFormat fileToExt(String fileName) {
        String fileExtStr = fileToExtStr(fileName);
        return SbomFormat.findSbomFormat(fileExtStr);
    }

    public static String fileToExtStr(String fileName) {
        if (!StringUtils.contains(fileName, ".")) {
            throw new RuntimeException("invalid sbom file without file extension: %s".formatted(fileName));
        }

        String fileExt = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        if (fileName.endsWith("rdf.xml")) {
            fileExt = "rdf.xml";
        }
        return fileExt;
    }

    public static SbomSpecification fileToSpec(SbomFormat format, byte[] fileContent) throws IOException {
        TypeReference<HashMap<String, Object>> typeReference = new TypeReference<>() {
        };
        HashMap<String, Object> map;
        if (format == SbomFormat.JSON) {
            map = Mapper.jsonSbomMapper.readValue(fileContent, typeReference);
        } else if (format == SbomFormat.XML) {
            map = Mapper.xmlSbomMapper.readValue(fileContent, typeReference);
        } else if (format == SbomFormat.YAML) {
            map = Mapper.yamlSbomMapper.readValue(fileContent, typeReference);
        } else if (format == SbomFormat.RDF) {
            throw new RuntimeException("not implemented for RDF");
        } else {
            throw new RuntimeException("invalid sbom file format type %s".formatted(format.name()));
        }

        if (StringUtils.equals((String) map.get("spdxVersion"), "SPDX-2.2")) {
            return SbomSpecification.SPDX_2_2;
        }
        if (StringUtils.equals((String) map.get("bomFormat"), "CycloneDX")) {
            if (StringUtils.equals((String) map.get("specVersion"), "1.4")) {
                return SbomSpecification.CYCLONEDX_1_4;
            }
        }
        throw new RuntimeException("failed to get sbom specification for sbom file %s");
    }

    private static <T> T fromJson(byte[] fileContent, Class<T> clazz) throws IOException {
        return Mapper.jsonSbomMapper.readValue(fileContent, clazz);
    }

    private static <T> T fromXml(byte[] fileContent, Class<T> clazz) throws IOException {
        return Mapper.xmlSbomMapper.readValue(fileContent, clazz);
    }

    private static <T> T fromYaml(byte[] fileContent, Class<T> clazz) throws IOException {
        return Mapper.yamlSbomMapper.readValue(fileContent, clazz);
    }

    private static <T> T fromRdf(byte[] fileContent, Class<T> clazz) throws IOException {
        throw new RuntimeException("not implemented for RDF");
    }

    public static <T> byte[] writeAsBytes(T sbomDocument, SbomFormat format) throws IOException {
        if (format == SbomFormat.JSON) {
            return toJsonBytes(sbomDocument);
        } else if (format == SbomFormat.XML) {
            return toXmlBytes(sbomDocument);
        } else if (format == SbomFormat.YAML) {
            return toYamlBytes(sbomDocument);
        } else if (format == SbomFormat.RDF) {
            return toRdfBytes(sbomDocument);
        } else {
            throw new RuntimeException("invalid format: %s".formatted(format));
        }
    }

    private static <T> byte[] toJsonBytes(T sbomDocument) throws IOException {
        return Mapper.jsonSbomMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(sbomDocument);
    }

    private static <T> byte[] toXmlBytes(T sbomDocument) throws IOException {
        return Mapper.xmlSbomMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(sbomDocument);
    }

    private static <T> byte[] toYamlBytes(T sbomDocument) throws IOException {
        return Mapper.yamlSbomMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(sbomDocument);
    }

    private static <T> byte[] toRdfBytes(T sbomDocument) throws IOException {
        throw new RuntimeException("not implemented for RDF");
    }
}
