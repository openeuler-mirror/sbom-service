package org.opensourceway.sbom.model.entity;

import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.util.UUID;

@Entity
public class ProductVulRef {

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    @Column(columnDefinition = "TEXT", name = "vul_id")
    private String vulId;

    @Column(columnDefinition = "TEXT", name = "issue_id")
    private String issueId;

    @Column(columnDefinition = "TEXT", name = "vul_status")
    private String vulStatus;

    @Column(columnDefinition = "TEXT", name = "issue_status")
    private String issueStatus;

    @Column(columnDefinition = "TEXT", name = "name")
    private String rpmName;

    @Column(columnDefinition = "TEXT" ,name = "download_location")
    private String repoLocation;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getVulId() {
        return vulId;
    }

    public void setVulId(String vulId) {
        this.vulId = vulId;
    }

    public String getIssueId() {
        return issueId;
    }

    public void setIssueId(String issueId) {
        this.issueId = issueId;
    }

    public String getVulStatus() {
        return vulStatus;
    }

    public void setVulStatus(String vulStatus) {
        this.vulStatus = vulStatus;
    }

    public String getIssueStatus() {
        return issueStatus;
    }

    public void setIssueStatus(String issueStatus) {
        this.issueStatus = issueStatus;
    }

    public String getRpmName() {
        return rpmName;
    }

    public void setRpmName(String rpmName) {
        this.rpmName = rpmName;
    }

    public String getRepoLocation() {
        return repoLocation;
    }

    public void setRepoLocation(String repoLocation) {
        this.repoLocation = repoLocation;
    }
}
