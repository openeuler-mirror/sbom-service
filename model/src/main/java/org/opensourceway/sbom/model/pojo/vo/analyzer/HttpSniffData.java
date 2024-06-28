package org.opensourceway.sbom.model.pojo.vo.analyzer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public record HttpSniffData(@JsonProperty(required = true) Integer pid,
                            @JsonProperty(required = true) Integer ppid,
                            @JsonProperty(required = true) String cmd,
                            @JsonProperty(required = true) String data) implements Serializable {}
